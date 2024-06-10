// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {JIT} from "../src/JIT.sol";
import {JITImplementation} from "../src/test/JITImplementation.sol";
import {Test} from "forge-std/Test.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {JITImplementation} from "../src/test/JITImplementation.sol";
import {PoolManager} from "@uniswap/v4-core/src/PoolManager.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {MockERC20} from "solmate/test/utils/mocks/MockERC20.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolModifyLiquidityTest} from "@uniswap/v4-core/src/test/PoolModifyLiquidityTest.sol";
import {PoolSwapTest} from "@uniswap/v4-core/src/test/PoolSwapTest.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {UniswapV4ERC20} from "v4-periphery/libraries/UniswapV4ERC20.sol";
import {FullMath} from "@uniswap/v4-core/src/libraries/FullMath.sol";
import {SafeCast} from "@uniswap/v4-core/src/libraries/SafeCast.sol";
import {HookEnabledSwapRouter} from "v4-periphery-test/utils/HookEnabledSwapRouter.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";

contract TestJIT is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    using SafeCast for uint256;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    event Initialize(
        PoolId poolId,
        Currency indexed currency0,
        Currency indexed currency1,
        uint24 fee,
        int24 tickSpacing,
        IHooks hooks
    );
    event ModifyPosition(
        PoolId indexed poolId, address indexed sender, int24 tickLower, int24 tickUpper, int256 liquidityDelta
    );
    event Swap(
        PoolId indexed id,
        address sender,
        int128 amount0,
        int128 amount1,
        uint160 sqrtPriceX96,
        uint128 liquidity,
        int24 tick,
        uint24 fee
    );

    HookEnabledSwapRouter router;
    /// @dev Min tick for full range with tick spacing of 60
    int24 internal constant MIN_TICK = -887220;
    /// @dev Max tick for full range with tick spacing of 60
    int24 internal constant MAX_TICK = -MIN_TICK;

    int24 constant TICK_SPACING = 60;
    uint16 constant LOCKED_LIQUIDITY = 1000;
    uint256 constant MAX_DEADLINE = 12329839823;
    uint256 constant MAX_TICK_LIQUIDITY = 11505069308564788430434325881101412;
    uint8 constant DUST = 30;

    MockERC20 token0;
    MockERC20 token1;
    MockERC20 token2;

    JITImplementation jit = JITImplementation(
        address(
            uint160(
                Hooks.BEFORE_INITIALIZE_FLAG | Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG
                    | Hooks.AFTER_SWAP_FLAG
            )
        )
    );

    PoolId id;

    PoolKey key2;
    PoolId id2;

    // For a pool that gets initialized with liquidity in setUp()
    PoolKey keyWithLiq;
    PoolId idWithLiq;

    function setUp() public {
        deployFreshManagerAndRouters();
        router = new HookEnabledSwapRouter(manager);
        MockERC20[] memory tokens = deployTokens(3, 2 ** 128);
        token0 = tokens[0];
        token1 = tokens[1];
        token2 = tokens[2];

        JITImplementation impl = new JITImplementation(manager, jit);
        vm.etch(address(jit), address(impl).code);

        key = createPoolKey(token0, token1);
        id = key.toId();

        key2 = createPoolKey(token1, token2);
        id2 = key.toId();

        keyWithLiq = createPoolKey(token0, token2);
        idWithLiq = keyWithLiq.toId();

        token0.approve(address(jit), type(uint256).max);
        token1.approve(address(jit), type(uint256).max);
        token2.approve(address(jit), type(uint256).max);
        token0.approve(address(router), type(uint256).max);
        token1.approve(address(router), type(uint256).max);
        token2.approve(address(router), type(uint256).max);

        initPool(keyWithLiq.currency0, keyWithLiq.currency1, jit, 3000, SQRT_PRICE_1_1, ZERO_BYTES);
        jit.addLiquidity(
            JIT.AddLiquidityParams(
                keyWithLiq.currency0,
                keyWithLiq.currency1,
                3000,
                100 ether,
                100 ether,
                99 ether,
                99 ether,
                address(this),
                MAX_DEADLINE
            )
        );
    }

    function testJIT_beforeInitialize_AllowsPoolCreation() public {
        PoolKey memory testKey = key;

        vm.expectEmit(true, true, true, true);
        emit Initialize(id, testKey.currency0, testKey.currency1, testKey.fee, testKey.tickSpacing, testKey.hooks);

        manager.initialize(testKey, SQRT_PRICE_1_1, ZERO_BYTES);

        (,, address liquidityToken) = jit.poolInfo(id);

        assertFalse(liquidityToken == address(0));
    }

    function testJIT_beforeInitialize_RevertsIfWrongSpacing() public {
        PoolKey memory wrongKey = PoolKey(key.currency0, key.currency1, 0, TICK_SPACING + 1, jit);

        vm.expectRevert(JIT.TickSpacingNotDefault.selector);
        manager.initialize(wrongKey, SQRT_PRICE_1_1, ZERO_BYTES);
    }

    function testJIT_addLiquidity_InitialAddSucceeds() public {
        manager.initialize(key, SQRT_PRICE_1_1, ZERO_BYTES);

        uint256 prevBalance0 = key.currency0.balanceOf(address(this));
        uint256 prevBalance1 = key.currency1.balanceOf(address(this));

        JIT.AddLiquidityParams memory addLiquidityParams = JIT.AddLiquidityParams(
            key.currency0, key.currency1, 3000, 10 ether, 10 ether, 9 ether, 9 ether, address(this), MAX_DEADLINE
        );

        jit.addLiquidity(addLiquidityParams);

        (bool hasAccruedFees,, address liquidityToken) = jit.poolInfo(id);
        uint256 liquidityTokenBal = UniswapV4ERC20(liquidityToken).balanceOf(address(this));

        assertEq(manager.getLiquidity(id), liquidityTokenBal + LOCKED_LIQUIDITY);

        assertEq(key.currency0.balanceOf(address(this)), prevBalance0 - 10 ether);
        assertEq(key.currency1.balanceOf(address(this)), prevBalance1 - 10 ether);

        assertEq(liquidityTokenBal, 10 ether - LOCKED_LIQUIDITY);
        assertEq(hasAccruedFees, false);
    }

    function testJIT_swap_Large_Large() public {
        PoolKey memory testKey = key;
        manager.initialize(testKey, SQRT_PRICE_1_1, ZERO_BYTES);

        jit.addLiquidity(
            JIT.AddLiquidityParams(
                key.currency0, key.currency1, 3000, 10 ether, 10 ether, 9 ether, 9 ether, address(this), MAX_DEADLINE
            )
        );

        IPoolManager.SwapParams memory params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: 1 ether, sqrtPriceLimitX96: SQRT_PRICE_1_2});
        HookEnabledSwapRouter.TestSettings memory settings =
            HookEnabledSwapRouter.TestSettings({takeClaims: false, settleUsingBurn: false});

        router.swap(testKey, params, settings, ZERO_BYTES);

        (bool hasAccruedFees,,) = jit.poolInfo(id);
        assertEq(hasAccruedFees, false);

        params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: 0.1 ether, sqrtPriceLimitX96: SQRT_PRICE_1_2});

        router.swap(testKey, params, settings, ZERO_BYTES);

        (hasAccruedFees,,) = jit.poolInfo(id);
        assertEq(hasAccruedFees, false);
    }

    function testJIT_swap_Large_Small_Large() public {
        PoolKey memory testKey = key;
        manager.initialize(testKey, SQRT_PRICE_1_1, ZERO_BYTES);

        jit.addLiquidity(
            JIT.AddLiquidityParams(
                key.currency0, key.currency1, 3000, 10 ether, 10 ether, 9 ether, 9 ether, address(this), MAX_DEADLINE
            )
        );

        IPoolManager.SwapParams memory params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: 1 ether, sqrtPriceLimitX96: SQRT_PRICE_1_2});
        HookEnabledSwapRouter.TestSettings memory settings =
            HookEnabledSwapRouter.TestSettings({takeClaims: false, settleUsingBurn: false});

        router.swap(testKey, params, settings, ZERO_BYTES);

        (bool hasAccruedFees,,) = jit.poolInfo(id);
        assertEq(hasAccruedFees, false);

        params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: 0.09 ether, sqrtPriceLimitX96: SQRT_PRICE_1_2});

        router.swap(testKey, params, settings, ZERO_BYTES);

        (hasAccruedFees,,) = jit.poolInfo(id);
        assertEq(hasAccruedFees, true);

        params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: 0.2 ether, sqrtPriceLimitX96: SQRT_PRICE_1_2});

        router.swap(testKey, params, settings, ZERO_BYTES);

        (hasAccruedFees,,) = jit.poolInfo(id);
        assertEq(hasAccruedFees, false);
    }

    function testJIT_swap_Large_Small_Large_Large_Small() public {
        PoolKey memory testKey = key;
        manager.initialize(testKey, SQRT_PRICE_1_1, ZERO_BYTES);

        jit.addLiquidity(
            JIT.AddLiquidityParams(
                key.currency0, key.currency1, 3000, 10 ether, 10 ether, 9 ether, 9 ether, address(this), MAX_DEADLINE
            )
        );

        IPoolManager.SwapParams memory params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: 1 ether, sqrtPriceLimitX96: SQRT_PRICE_1_2});
        HookEnabledSwapRouter.TestSettings memory settings =
            HookEnabledSwapRouter.TestSettings({takeClaims: false, settleUsingBurn: false});

        router.swap(testKey, params, settings, ZERO_BYTES);

        (bool hasAccruedFees,,) = jit.poolInfo(id);
        assertEq(hasAccruedFees, false);

        params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: 0.09 ether, sqrtPriceLimitX96: SQRT_PRICE_1_2});

        router.swap(testKey, params, settings, ZERO_BYTES);

        (hasAccruedFees,,) = jit.poolInfo(id);
        assertEq(hasAccruedFees, true);

        params =
            IPoolManager.SwapParams({zeroForOne: true, amountSpecified: 0.2 ether, sqrtPriceLimitX96: SQRT_PRICE_1_2});

        router.swap(testKey, params, settings, ZERO_BYTES);

        (hasAccruedFees,,) = jit.poolInfo(id);
        assertEq(hasAccruedFees, false);

        params =
            IPoolManager.SwapParams({zeroForOne: false, amountSpecified: 1 ether, sqrtPriceLimitX96: SQRT_PRICE_2_1});

        router.swap(testKey, params, settings, ZERO_BYTES);

        (hasAccruedFees,,) = jit.poolInfo(id);
        assertEq(hasAccruedFees, false);

        params =
            IPoolManager.SwapParams({zeroForOne: false, amountSpecified: 0.09 ether, sqrtPriceLimitX96: SQRT_PRICE_2_1});

        router.swap(testKey, params, settings, ZERO_BYTES);

        (hasAccruedFees,,) = jit.poolInfo(id);
        assertEq(hasAccruedFees, true);
    }

    //////!!!!
    function createPoolKey(MockERC20 tokenA, MockERC20 tokenB) internal view returns (PoolKey memory) {
        if (address(tokenA) > address(tokenB)) (tokenA, tokenB) = (tokenB, tokenA);
        return PoolKey(Currency.wrap(address(tokenA)), Currency.wrap(address(tokenB)), 3000, TICK_SPACING, jit);
    }
}
