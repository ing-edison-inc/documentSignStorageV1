// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {DocumentRegistry} from "../src/DocumentRegistry.sol";

contract DeployScript is Script {
    function run() external returns (DocumentRegistry) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying with account:", deployer);
        console.log("Account balance:", deployer.balance);

        vm.startBroadcast(deployerPrivateKey);

        DocumentRegistry documentRegistry = new DocumentRegistry();

        console.log("DocumentRegistry deployed at:", address(documentRegistry));

        vm.stopBroadcast();

        return documentRegistry;
    }
}
