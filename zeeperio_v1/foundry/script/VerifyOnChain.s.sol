// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import {console2} from "forge-std/console2.sol";
import "../src/ZeeperioBN254Verifier.sol";

contract VerifyOnChain is Script {
    using stdJson for string;

    uint8 constant KIND_MAIN = 0;
    uint8 constant KIND_INCLUSION = 1;
    uint8 constant KIND_RECEIPT = 2;

    function run() external {
        string memory root = vm.projectRoot();
        ZeeperioBN254Verifier verifier = new ZeeperioBN254Verifier();

        _verifyMain(verifier, string.concat(root, "/fixtures/calldata_main.json"));
        _verifyInclusion(verifier, string.concat(root, "/fixtures/calldata_inclusion.json"));
        _verifyReceipt(verifier, string.concat(root, "/fixtures/calldata_receipt.json"));
        console2.log("All fixtures verified against fresh BN254 verifier");
    }

    function _verifyMain(ZeeperioBN254Verifier verifier, string memory path) internal {
        bytes memory proofCalldata = _loadCalldata(path);
        ZeeperioBN254Verifier.Proof memory proof = _decode(proofCalldata);
        require(proof.kind == KIND_MAIN, "unexpected main kind");
        require(verifier.verifyMain(proofCalldata), "main proof failed");
        console2.log("verifyMain OK (%s)", path);
    }

    function _verifyInclusion(ZeeperioBN254Verifier verifier, string memory path) internal {
        bytes memory proofCalldata = _loadCalldata(path);
        ZeeperioBN254Verifier.Proof memory proof = _decode(proofCalldata);
        require(proof.kind == KIND_INCLUSION, "unexpected inclusion kind");
        require(verifier.verifyInclusion(proofCalldata), "inclusion proof failed");
        console2.log("verifyInclusion OK (%s)", path);
    }

    function _verifyReceipt(ZeeperioBN254Verifier verifier, string memory path) internal {
        bytes memory proofCalldata = _loadCalldata(path);
        ZeeperioBN254Verifier.Proof memory proof = _decode(proofCalldata);
        require(proof.kind == KIND_RECEIPT, "unexpected receipt kind");
        require(verifier.verifyReceipt(proofCalldata), "receipt proof failed");
        console2.log("verifyReceipt OK (%s)", path);
    }

    function _loadCalldata(string memory path) internal view returns (bytes memory) {
        string memory json = vm.readFile(path);
        string memory calldataHex = stdJson.readString(json, ".calldata");
        return vm.parseBytes(calldataHex);
    }

    function _decode(bytes memory proofCalldata) internal pure returns (ZeeperioBN254Verifier.Proof memory proof) {
        proof = abi.decode(proofCalldata, (ZeeperioBN254Verifier.Proof));
    }
}
