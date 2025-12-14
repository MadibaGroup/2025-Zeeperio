// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {ZeeperioBN254Verifier} from "../src/ZeeperioBN254Verifier.sol";
import {console2} from "forge-std/console2.sol";

contract DeployZeeperio is Script {
    function run() external {
        vm.startBroadcast();
        ZeeperioBN254Verifier verifier = new ZeeperioBN254Verifier();
        vm.stopBroadcast();
        console2.log("deployed at", address(verifier));
    }
}
