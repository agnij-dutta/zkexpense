// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @notice Interface implemented by the bb-generated UltraHonk Solidity verifiers.
interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool);
}

/// @title ExpenseAttestation
/// @author Agnij Dutta
/// @notice On-chain registry of zkExpense reports. A principal registers an agent mandate
///         (payer wallet, asset, chain, approved-vendor root, budget cap). Anyone can then submit
///         a zero-knowledge expense report for that agent; it is recorded only if the proof verifies
///         and the report's public inputs match the mandate. Consecutive reports must cover
///         back-to-back periods and continue the same payment hash chain, so an agent cannot skip
///         a period or restart its history.
/// @dev Public input layout (15 fields, fixed by circuits/lib):
///      0 payer, 1 asset, 2 chainId, 3 periodStart, 4 periodEnd, 5 budget, 6 discloseTotal,
///      7 chainIn, 8 logRoot, 9 vendorRoot, 10 count, 11 underBudget, 12 disclosedTotal,
///      13 totalCommit, 14 chainOut.
///      Trust assumptions: the owner can add (never replace) verifiers and pause submissions.
contract ExpenseAttestation is Ownable2Step, Pausable {
    uint256 public constant NUM_PUBLIC_INPUTS = 15;

    /// @dev Packed into 5 slots.
    struct Mandate {
        address principal; // slot 0
        uint96 budgetCap; //  slot 0, atomic asset units
        address payer; //     slot 1
        uint64 chainId; //    slot 1
        uint32 reports; //    slot 1, number of attested reports
        address asset; //     slot 2
        uint64 lastPeriodEnd; // slot 2
        bytes32 vendorRoot; // slot 3
        bytes32 lastChainOut; // slot 4
    }

    /// @dev Packed into 3 slots. Full public inputs are emitted, their hash is stored.
    struct Attestation {
        bytes32 logRoot;
        bytes32 publicInputsHash;
        uint64 periodStart;
        uint64 periodEnd;
        uint64 attestedAt;
        uint32 count;
        bool underBudget;
    }

    mapping(bytes32 circuitId => IHonkVerifier) public verifiers;
    mapping(bytes32 agentId => Mandate) internal _mandates;
    mapping(bytes32 agentId => mapping(uint256 index => Attestation)) internal _attestations;

    event VerifierAdded(bytes32 indexed circuitId, address verifier);
    event AgentRegistered(bytes32 indexed agentId, address indexed principal, address indexed payer);
    event MandateUpdated(bytes32 indexed agentId, bytes32 vendorRoot, uint96 budgetCap);
    event ReportAttested(
        bytes32 indexed agentId,
        uint256 indexed index,
        bytes32 indexed circuitId,
        uint64 periodStart,
        uint64 periodEnd,
        bytes32 logRoot,
        uint32 count,
        bool underBudget,
        bytes32[] publicInputs
    );
    event BudgetExceeded(bytes32 indexed agentId, uint256 indexed index, uint256 budget);

    error ZeroAddress();
    error VerifierExists(bytes32 circuitId);
    error UnknownCircuit(bytes32 circuitId);
    error AgentExists(bytes32 agentId);
    error UnknownAgent(bytes32 agentId);
    error NotPrincipal(address caller);
    error BadPublicInputsLength(uint256 got);
    error MandateMismatch(uint256 field);
    error BudgetAboveCap(uint256 budget, uint256 cap);
    error PeriodNotContiguous(uint256 expectedStart, uint256 gotStart);
    error PeriodNotOver(uint256 periodEnd);
    error BadPeriod();
    error ChainBreak(bytes32 expected, bytes32 got);
    error InvalidProof();

    constructor(address owner_) Ownable(owner_) {}

    // ------------------------------------------------------------------ admin

    /// @notice Register the verifier for a circuit id (e.g. keccak256("batch_256")). Append-only.
    /// @param circuitId Identifier of the zkExpense circuit
    /// @param verifier bb-generated verifier contract for that circuit
    function addVerifier(bytes32 circuitId, IHonkVerifier verifier) external onlyOwner {
        if (address(verifier) == address(0)) revert ZeroAddress();
        if (address(verifiers[circuitId]) != address(0)) revert VerifierExists(circuitId);
        verifiers[circuitId] = verifier;
        emit VerifierAdded(circuitId, address(verifier));
    }

    /// @notice Pause report submission (emergency only).
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Resume report submission.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ------------------------------------------------------------------ principals

    /// @notice Register an agent under the caller as principal.
    /// @param agentId Agent identifier (e.g. an ERC-8004 agent id)
    /// @param payer The agent's paying wallet (x402 `payer`)
    /// @param asset Settlement asset (e.g. USDC)
    /// @param chainId Settlement chain id
    /// @param vendorRoot Salted Poseidon2 root of the approved vendor set
    /// @param budgetCap Maximum per-period budget a report may claim, in atomic units
    function registerAgent(
        bytes32 agentId,
        address payer,
        address asset,
        uint64 chainId,
        bytes32 vendorRoot,
        uint96 budgetCap
    ) external {
        if (payer == address(0) || asset == address(0)) revert ZeroAddress();
        if (_mandates[agentId].principal != address(0)) revert AgentExists(agentId);
        _mandates[agentId] = Mandate({
            principal: msg.sender,
            budgetCap: budgetCap,
            payer: payer,
            chainId: chainId,
            reports: 0,
            asset: asset,
            lastPeriodEnd: 0,
            vendorRoot: vendorRoot,
            lastChainOut: bytes32(0)
        });
        emit AgentRegistered(agentId, msg.sender, payer);
        emit MandateUpdated(agentId, vendorRoot, budgetCap);
    }

    /// @notice Change the approved vendor set and budget cap for future reports.
    /// @param agentId Agent to update
    /// @param vendorRoot New vendor root
    /// @param budgetCap New budget cap
    function updateMandate(bytes32 agentId, bytes32 vendorRoot, uint96 budgetCap) external {
        Mandate storage m = _mandates[agentId];
        if (m.principal != msg.sender) revert NotPrincipal(msg.sender);
        m.vendorRoot = vendorRoot;
        m.budgetCap = budgetCap;
        emit MandateUpdated(agentId, vendorRoot, budgetCap);
    }

    // ------------------------------------------------------------------ reports

    /// @notice Verify and record an expense report. Permissionless: the proof authenticates itself.
    /// @param agentId Agent the report is for
    /// @param circuitId Circuit that produced the proof
    /// @param proof UltraHonk proof bytes (proof.json `proof`)
    /// @param publicInputs The 15 public inputs (proof.json `publicInputs`)
    /// @return index Sequence number of the recorded report
    function submitReport(
        bytes32 agentId,
        bytes32 circuitId,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external whenNotPaused returns (uint256 index) {
        if (publicInputs.length != NUM_PUBLIC_INPUTS) revert BadPublicInputsLength(publicInputs.length);
        IHonkVerifier verifier = verifiers[circuitId];
        if (address(verifier) == address(0)) revert UnknownCircuit(circuitId);
        Mandate storage m = _mandates[agentId];
        if (m.principal == address(0)) revert UnknownAgent(agentId);

        _checkMandate(m, publicInputs);

        // A non-reverting `false` is treated the same as a revert.
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        index = _record(agentId, m, publicInputs);
        emit ReportAttested(
            agentId,
            index,
            circuitId,
            uint64(uint256(publicInputs[3])),
            uint64(uint256(publicInputs[4])),
            publicInputs[8],
            uint32(uint256(publicInputs[10])),
            uint256(publicInputs[11]) == 1,
            publicInputs
        );
        if (uint256(publicInputs[11]) != 1) emit BudgetExceeded(agentId, index, uint256(publicInputs[5]));
    }

    /// @dev Binds the proof's public inputs to the agent's mandate and history.
    function _checkMandate(Mandate storage m, bytes32[] calldata pi) internal view {
        if (uint256(pi[0]) != uint256(uint160(m.payer))) revert MandateMismatch(0);
        if (uint256(pi[1]) != uint256(uint160(m.asset))) revert MandateMismatch(1);
        if (uint256(pi[2]) != m.chainId) revert MandateMismatch(2);
        if (pi[9] != m.vendorRoot) revert MandateMismatch(9);

        uint256 budget = uint256(pi[5]);
        if (budget > m.budgetCap) revert BudgetAboveCap(budget, m.budgetCap);

        uint256 start = uint256(pi[3]);
        uint256 end = uint256(pi[4]);
        if (start > end || end > type(uint64).max) revert BadPeriod();
        if (end >= block.timestamp) revert PeriodNotOver(end);
        if (m.reports > 0 && start != uint256(m.lastPeriodEnd) + 1) {
            revert PeriodNotContiguous(uint256(m.lastPeriodEnd) + 1, start);
        }
        if (pi[7] != m.lastChainOut) revert ChainBreak(m.lastChainOut, pi[7]);
    }

    /// @dev Stores the attestation and advances the agent's history.
    function _record(bytes32 agentId, Mandate storage m, bytes32[] calldata pi) internal returns (uint256 index) {
        index = m.reports;
        _attestations[agentId][index] = Attestation({
            logRoot: pi[8],
            publicInputsHash: keccak256(abi.encodePacked(pi)),
            periodStart: uint64(uint256(pi[3])),
            periodEnd: uint64(uint256(pi[4])),
            attestedAt: uint64(block.timestamp),
            count: uint32(uint256(pi[10])),
            underBudget: uint256(pi[11]) == 1
        });
        // casting to 'uint32' is safe because 2^32 reports would take billions of years of periods
        // forge-lint: disable-next-line(unsafe-typecast)
        m.reports = uint32(index + 1);
        m.lastPeriodEnd = uint64(uint256(pi[4]));
        m.lastChainOut = pi[14];
    }

    // ------------------------------------------------------------------ views

    /// @notice The mandate registered for an agent.
    /// @param agentId Agent identifier
    /// @return The stored mandate
    function mandate(bytes32 agentId) external view returns (Mandate memory) {
        return _mandates[agentId];
    }

    /// @notice A recorded report.
    /// @param agentId Agent identifier
    /// @param index Report sequence number
    /// @return The stored attestation
    function attestation(bytes32 agentId, uint256 index) external view returns (Attestation memory) {
        return _attestations[agentId][index];
    }

    /// @notice Check that a full set of public inputs is exactly what was attested.
    /// @param agentId Agent identifier
    /// @param index Report sequence number
    /// @param publicInputs Public inputs to compare
    /// @return True if they hash to the stored value
    function isAttested(bytes32 agentId, uint256 index, bytes32[] calldata publicInputs) external view returns (bool) {
        bytes32 h = _attestations[agentId][index].publicInputsHash;
        return h != bytes32(0) && h == keccak256(abi.encodePacked(publicInputs));
    }
}
