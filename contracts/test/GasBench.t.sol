// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test, console2} from "forge-std/Test.sol";
import {ExpenseAttestation, IHonkVerifier} from "../src/ExpenseAttestation.sol";
import {Batch64Verifier} from "../src/verifiers/Batch64Verifier.sol";
import {Batch256Verifier} from "../src/verifiers/Batch256Verifier.sol";
import {Batch512Verifier} from "../src/verifiers/Batch512Verifier.sol";
import {Batch1024Verifier} from "../src/verifiers/Batch1024Verifier.sol";
import {Agg1024x4Verifier} from "../src/verifiers/Agg1024x4Verifier.sol";

/// @notice Gas for verifying real proofs written by scripts/bench.mjs (skips missing fixtures).
contract GasBench is Test {
    function _case(string memory id, IHonkVerifier v, string memory circuit) internal {
        string memory path = string.concat(vm.projectRoot(), "/test/fixtures/bench/", id, ".json");
        if (!vm.exists(path)) {
            console2.log("skip (no fixture)", id);
            return;
        }
        string memory json = vm.readFile(path);
        bytes memory proof = vm.parseJsonBytes(json, ".proof");
        bytes32[] memory pi = vm.parseJsonBytes32Array(json, ".publicInputs");

        uint256 g = gasleft();
        assertTrue(v.verify(proof, pi));
        uint256 verifyGas = g - gasleft();

        ExpenseAttestation reg = new ExpenseAttestation(address(this));
        bytes32 cid = keccak256(bytes(circuit));
        reg.addVerifier(cid, v);
        reg.registerAgent(
            "a",
            address(uint160(uint256(pi[0]))),
            address(uint160(uint256(pi[1]))),
            uint64(uint256(pi[2])),
            pi[9],
            type(uint96).max,
            uint64(uint256(pi[3])),
            0
        );
        vm.warp(uint256(pi[4]) + 1);
        g = gasleft();
        reg.submitReport(address(this), "a", cid, proof, pi);
        uint256 submitGas = g - gasleft();

        // Intrinsic calldata cost of a submitReport tx (EIP-2028: 4 gas/zero byte, 16 gas/non-zero).
        bytes memory data = abi.encodeCall(ExpenseAttestation.submitReport, (address(this), "a", cid, proof, pi));
        uint256 cd;
        for (uint256 i; i < data.length; ++i) {
            cd += data[i] == 0 ? 4 : 16;
        }
        console2.log(string.concat("GAS ", id, " verify=", vm.toString(verifyGas), " submit=", vm.toString(submitGas), " calldata=", vm.toString(cd)));
    }

    function test_gas_all() public {
        _case("n64", IHonkVerifier(address(new Batch64Verifier())), "batch_64");
        _case("n256", IHonkVerifier(address(new Batch256Verifier())), "batch_256");
        _case("n347", IHonkVerifier(address(new Batch512Verifier())), "batch_512");
        _case("n512", IHonkVerifier(address(new Batch512Verifier())), "batch_512");
        _case("n1024", IHonkVerifier(address(new Batch1024Verifier())), "batch_1024");
        _case("n4096", IHonkVerifier(address(new Agg1024x4Verifier())), "agg_1024x4");
    }
}
