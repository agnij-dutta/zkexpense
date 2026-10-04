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
///         (payer wallet, asset, chain, approved-vendor root, budget cap, first period start,
///         minimum period length). Anyone can then submit a zero-knowledge expense report for
///         that mandate; it is recorded only if the proof verifies and the report's public inputs
///         match the mandate. Reports must cover back-to-back periods starting at the mandate's
///         first period and continue the same payment hash chain, so an agent cannot skip or hide
///         a period, restart its history, or split a period to multiply its budget cap.
/// @dev Public input layout (15 fields, fixed by circuits/lib):
///      0 payer, 1 asset, 2 chainId, 3 periodStart, 4 periodEnd, 5 budget, 6 discloseTotal,
///      7 chainIn, 8 logRoot, 9 vendorRoot, 10 count, 11 underBudget, 12 disclosedTotal,
///      13 totalCommit, 14 chainOut.
///      Mandates are namespaced by principal, so registering an agent id cannot be front-run or
///      squatted by someone else. Trust assumptions: the owner can add (never replace) verifiers
///      and pause submissions.
contract ExpenseAttestation is Ownable2Step, Pausable {
    uint256 public constant NUM_PUBLIC_INPUTS = 15;

    /// @dev BN254 scalar field modulus. Public inputs are field elements; only canonical encodings
    ///      (< MODULUS) are accepted so that one statement has exactly one byte representation.
    uint256 internal constant MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Packed into 5 slots. A mandate exists iff `payer != address(0)`.
    struct Mandate {
        uint96 budgetCap; //        slot 0, atomic asset units, per report
        uint32 minPeriodLength; //  slot 0, seconds; a report must cover at least this long
        uint32 reports; //          slot 0, number of attested reports
        address payer; //           slot 1
        uint64 chainId; //          slot 1
        address asset; //           slot 2
        uint64 nextPeriodStart; //  slot 2, the next report must start exactly here
        bytes32 vendorRoot; //      slot 3
        bytes32 lastChainOut; //    slot 4
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
    mapping(address principal => mapping(bytes32 agentId => Mandate)) internal _mandates;
    mapping(address principal => mapping(bytes32 agentId => mapping(uint256 index => Attestation))) internal
        _attestations;

    event VerifierAdded(bytes32 indexed circuitId, address verifier);
    event AgentRegistered(
        address indexed principal,
        bytes32 indexed agentId,
        address indexed payer,
        uint64 firstPeriodStart,
        uint32 minPeriodLength
    );
    event MandateUpdated(address indexed principal, bytes32 indexed agentId, bytes32 vendorRoot, uint96 budgetCap);
    event ReportAttested(
        address indexed principal,
        bytes32 indexed agentId,
        uint256 indexed index,
        bytes32 circuitId,
        uint64 periodStart,
        uint64 periodEnd,
        bytes32 logRoot,
        uint32 count,
        bool underBudget,
        bytes32[] publicInputs
    );
    event BudgetExceeded(address indexed principal, bytes32 indexed agentId, uint256 indexed index, uint256 budget);

    error ZeroAddress();
    error VerifierExists(bytes32 circuitId);
    error UnknownCircuit(bytes32 circuitId);
    error AgentExists(address principal, bytes32 agentId);
    error UnknownAgent(address principal, bytes32 agentId);
    error BadPublicInputsLength(uint256 got);
    error NonCanonicalInput(uint256 index);
    error MandateMismatch(uint256 field);
    error BudgetAboveCap(uint256 budget, uint256 cap);
    error PeriodNotContiguous(uint256 expectedStart, uint256 gotStart);
    error PeriodNotOver(uint256 periodEnd);
    error PeriodTooShort(uint256 length, uint256 minLength);
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

    /// @notice Register an agent mandate under the caller (`msg.sender` becomes its principal).
    /// @dev The first report must start exactly at `firstPeriodStart`, so an agent cannot hide its
    ///      early history by simply starting to report later. `minPeriodLength` stops an agent from
    ///      splitting one period into many short reports that each claim the full `budgetCap`.
    /// @param agentId Agent identifier (e.g. an ERC-8004 agent id), scoped to the caller
    /// @param payer The agent's paying wallet (x402 `payer`)
    /// @param asset Settlement asset (e.g. USDC)
    /// @param chainId Settlement chain id
    /// @param vendorRoot Salted Poseidon2 root of the approved vendor set
    /// @param budgetCap Maximum budget a single report may claim, in atomic units
    /// @param firstPeriodStart Unix time the first report's period must start at
    /// @param minPeriodLength Minimum period a report may cover, in seconds (e.g. 28 days)
    function registerAgent(
        bytes32 agentId,
        address payer,
        address asset,
        uint64 chainId,
        bytes32 vendorRoot,
        uint96 budgetCap,
        uint64 firstPeriodStart,
        uint32 minPeriodLength
    ) external {
        if (payer == address(0) || asset == address(0)) revert ZeroAddress();
        Mandate storage m = _mandates[msg.sender][agentId];
        if (m.payer != address(0)) revert AgentExists(msg.sender, agentId);
        m.budgetCap = budgetCap;
        m.minPeriodLength = minPeriodLength;
        m.payer = payer;
        m.chainId = chainId;
        m.asset = asset;
        m.nextPeriodStart = firstPeriodStart;
        m.vendorRoot = vendorRoot;
        emit AgentRegistered(msg.sender, agentId, payer, firstPeriodStart, minPeriodLength);
        emit MandateUpdated(msg.sender, agentId, vendorRoot, budgetCap);
    }

    /// @notice Change the approved vendor set and budget cap for future reports of the caller's agent.
    /// @param agentId Agent to update (scoped to the caller)
    /// @param vendorRoot New vendor root
    /// @param budgetCap New budget cap
    function updateMandate(bytes32 agentId, bytes32 vendorRoot, uint96 budgetCap) external {
        Mandate storage m = _mandates[msg.sender][agentId];
        if (m.payer == address(0)) revert UnknownAgent(msg.sender, agentId);
        m.vendorRoot = vendorRoot;
        m.budgetCap = budgetCap;
        emit MandateUpdated(msg.sender, agentId, vendorRoot, budgetCap);
    }

    // ------------------------------------------------------------------ reports

    /// @notice Verify and record an expense report. Permissionless: the proof authenticates itself,
    ///         and the period sequence makes every report recordable exactly once per mandate.
    /// @param principal Principal that registered the mandate
    /// @param agentId Agent the report is for
    /// @param circuitId Circuit that produced the proof
    /// @param proof UltraHonk proof bytes (proof.json `proof`)
    /// @param publicInputs The 15 public inputs (proof.json `publicInputs`)
    /// @return index Sequence number of the recorded report
    function submitReport(
        address principal,
        bytes32 agentId,
        bytes32 circuitId,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external whenNotPaused returns (uint256 index) {
        if (publicInputs.length != NUM_PUBLIC_INPUTS) {
            revert BadPublicInputsLength(publicInputs.length);
        }
        IHonkVerifier verifier = verifiers[circuitId];
        if (address(verifier) == address(0)) revert UnknownCircuit(circuitId);
        Mandate storage m = _mandates[principal][agentId];
        if (m.payer == address(0)) revert UnknownAgent(principal, agentId);

        _checkMandate(m, publicInputs);

        // A non-reverting `false` is treated the same as a revert.
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        index = _record(principal, agentId, m, publicInputs);
        emit ReportAttested(
            principal,
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
        if (uint256(publicInputs[11]) != 1) {
            emit BudgetExceeded(principal, agentId, index, uint256(publicInputs[5]));
        }
    }

    /// @dev Binds the proof's public inputs to the agent's mandate and history.
    function _checkMandate(Mandate storage m, bytes32[] calldata pi) internal view {
        for (uint256 i; i < NUM_PUBLIC_INPUTS; ++i) {
            if (uint256(pi[i]) >= MODULUS) revert NonCanonicalInput(i);
        }
        if (uint256(pi[0]) != uint256(uint160(m.payer))) revert MandateMismatch(0);
        if (uint256(pi[1]) != uint256(uint160(m.asset))) revert MandateMismatch(1);
        if (uint256(pi[2]) != m.chainId) revert MandateMismatch(2);
        if (pi[9] != m.vendorRoot) revert MandateMismatch(9);

        uint256 budget = uint256(pi[5]);
        if (budget > m.budgetCap) revert BudgetAboveCap(budget, m.budgetCap);

        uint256 start = uint256(pi[3]);
        uint256 end = uint256(pi[4]);
        if (start > end || end >= type(uint64).max) revert BadPeriod();
        if (end >= block.timestamp) revert PeriodNotOver(end);
        if (start != m.nextPeriodStart) revert PeriodNotContiguous(m.nextPeriodStart, start);
        if (end - start + 1 < m.minPeriodLength) revert PeriodTooShort(end - start + 1, m.minPeriodLength);
        if (pi[7] != m.lastChainOut) revert ChainBreak(m.lastChainOut, pi[7]);
    }

    /// @dev Stores the attestation and advances the agent's history.
    function _record(address principal, bytes32 agentId, Mandate storage m, bytes32[] calldata pi)
        internal
        returns (uint256 index)
    {
        index = m.reports;
        _attestations[principal][agentId][index] = Attestation({
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
        // casting to 'uint64' is safe because _checkMandate requires end < type(uint64).max
        // forge-lint: disable-next-line(unsafe-typecast)
        m.nextPeriodStart = uint64(uint256(pi[4]) + 1);
        m.lastChainOut = pi[14];
    }

    // ------------------------------------------------------------------ views

    /// @notice The mandate a principal registered for an agent.
    /// @param principal Principal that registered the mandate
    /// @param agentId Agent identifier
    /// @return The stored mandate (all zero if none)
    function mandate(address principal, bytes32 agentId) external view returns (Mandate memory) {
        return _mandates[principal][agentId];
    }

    /// @notice A recorded report.
    /// @param principal Principal that registered the mandate
    /// @param agentId Agent identifier
    /// @param index Report sequence number
    /// @return The stored attestation (all zero if none)
    function attestation(address principal, bytes32 agentId, uint256 index) external view returns (Attestation memory) {
        return _attestations[principal][agentId][index];
    }

    /// @notice Check that a full set of public inputs is exactly what was attested.
    /// @param principal Principal that registered the mandate
    /// @param agentId Agent identifier
    /// @param index Report sequence number
    /// @param publicInputs Public inputs to compare
    /// @return True if they hash to the stored value
    function isAttested(address principal, bytes32 agentId, uint256 index, bytes32[] calldata publicInputs)
        external
        view
        returns (bool)
    {
        bytes32 h = _attestations[principal][agentId][index].publicInputsHash;
        return h != bytes32(0) && h == keccak256(abi.encodePacked(publicInputs));
    }
}
