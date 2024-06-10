// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {JIT} from "../JIT.sol";
import {BaseHook} from "v4-periphery/BaseHook.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";

contract JITImplementation is JIT {
    constructor(IPoolManager _poolManager, JIT addressToEtch) JIT(_poolManager) {
        Hooks.validateHookPermissions(addressToEtch, getHookPermissions());
    }

    // make this a no-op in testing
    function validateHookAddress(BaseHook _this) internal pure override {}
}
