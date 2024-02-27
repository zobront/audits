<table>
    <tr><th></th><th></th></tr>
    <tr>
        <td><img src="https://styles.redditmedia.com/t5_45q11m/styles/communityIcon_iqrykrjom8p61.png" width="250" height="250" /></td>
        <td>
            <h1>StakeDAO Audit Report</h1>
            <h2>OnlyBoost</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: November 16 to 22, 2023</p>
        </td>
    </tr>
</table>

# About **StakeDAO's OnlyBoost**

Stake DAO is a non-custodial platform providing the best yield on governance and LP tokens. OnlyBoost is a strategy that automatically allocates yield between StakeDAO and Convex, ensuring optimal returns for users.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

The [stake-dao/only-boost](https://github.com/stake-dao/only-boost) repository was audited at commit [22dfaaf6a0e4aba103db0445f6b99f8bc10aa803]( https://github.com/stake-dao/only-boost/tree/22dfaaf6a0e4aba103db0445f6b99f8bc10aa803).

The following contracts were in scope:
- src/CRVStrategy.sol
- src/strategy/Strategy.sol
- src/strategy/only-boost/OnlyBoost.sol
- src/optimizer/Optimizer.sol
- src/staking/Vault.sol
- src/libraries/SafeExecute.sol
- src/fallbacks/ConvexImplementation.sol
- src/fallbacks/ConvexMinimalProxyFactory.sol
- src/factory/PoolFactory.sol
- src/factory/curve/CRVPoolFactory.sol

After completion of the fixes, the [PR #66](https://github.com/stake-dao/only-boost/pull/66) was reviewed.


# Summary of Findings

| Identifier     | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| H-01 | `rebalance()` will cause pools to become unbalanced | High | ✓ |
| M-01 | CRV claimed as an extraRewardToken will be stuck in Strategy | Medium | ✓ |
| M-02 | Balancing mechanism will often be imprecise | Medium | ✓ |
| M-03 | Optimizer will misallocate when StakeDAO is above full boost | Medium | |
| M-04 | Curve gauges with 7+ extra reward tokens cannot be integrated | Medium | ✓ |
| M-05 | Deployment script mismatches gauges and reward distributors | Medium | ✓ |
| L-01 | Optimizer rounds negative feeDiff values to zero | Low | |
| L-02 | Fallback & vault fees must remain at zero for Optimizer to work as intended | Low | |
| L-03 | `setGauge()` and `setRewardDistributor()` should revoke old approvals | Low | ✓ |
| L-04 | `_isValidToken()` check should not allow SDT | Low | ✓ |
| L-05 | Reward Distributor implementation uses vulnerable Vyper version | Low | ✓ |
| I-01 | Strong trust assumption that Convex will act in good faith | Informational | |

# Detailed Findings

## [H-01] `rebalance()` will cause pools to become unbalanced

The OnlyBoost strategy implements a `rebalance()` function that is intended to balance the funds properly between the StakeDAO locker and Convex.

The implementation is based on the assumption that, although withdrawals will not always leave the two sides allocated correctly, deposits should, and therefore withdrawing and depositing again should lead to a balanced state.

However, the optimized deposit function is based on the following assumption from the whitepaper:

> As S = S0 + x and bsd = bsd0 + x where S0 and bsd0 are initial deposits, and x is the additional deposit needed to reach the target SD balance, we have here a non linear problem which leads to a second degree polynomial problem with complex roots. The complexity of this solution is such that gas costs involved in reaching it are higher than the yield optimization it provides.

> However, we can assume that for small deposits, S ~= S0, and get back to a linear problem again.

This means that, in order for the deposit optimization to work correctly, we must assume that the size of the deposit is small enough that the gauge token balances after the deposit are negligibly different from the gauge token balances before the deposit. Therefore, the optimal amount calculated before the deposit will still hold.

However, in the event of a `rebalance()`, we perform the following:
- withdraw ALL deposits made via the Convex fallback
- withdraw ALL deposits made via the StakeDAO locker
- call `deposit()` with the sum of all of these

In this case, it is not safe to assume the size of the deposit is negligibly small, and in fact will almost always be quite large. This leads us to make the full deposit based on the state of boosts with no StakeDAO allocation, which can lead to very unbalanced results.

### Proof of Concept

In order to illustrate this problem, let's look at a simple example:
- Convex has 48.3% of the total supply of veCRV (currently accurate)
- StakeDAO has 9.4% of the total supply of veCRV (currently accurate)
- For a given gauge, Convex natively holds 48.3% of the total supply of gauge tokens
- For the same gauge, OnlyBoost holds 9.4% of the total supply

The optimal allocation in this situation occurs where all OnlyBoost holdings are allocated to StakeDAO, thus ensuring a full 2.5X boost for all users.

However, regardless of the current balance, if we call `rebalance()` in this situation, we will perform the following:
- withdraw all 9.4% of the supply of gauge tokens from the StakeDAO locker
- call `optimizer.deposit()`, which will determine that, since Convex has a full boost, all allocation should go there
- all 9.4% of the allocation will be send to the Convex fallback

The result will be the fallback holding 57.7% of the gauge tokens (2.26X boost), while StakeDAO will hold no tokens.

Note: This example is simple to follow because it uses the shortcut that Convex will get all allocation when it has full boost. However, since all surplus above the optimal StakeDAO balance is always allocated to Convex (rather than trying to create an optimal split with the surplus), the same problem will hold at lower boosts as well.

This problem becomes worse as OnlyBoost becomes more successful. If users move their funds over to find optimal allocations in enough quantity that Convex's native deposits give them full boost, then every call to `rebalance()` will always send all funds to Convex, defeating the purpose of the protocol.

### Recommendation

Since we know the total amount deposited that we are trying to optimize, we can calculate the values before withdrawing in order to get a precise result.

### Review

Fixed in commit [670313c552e59646b00a7540d54b444f2228c3a5](https://github.com/stake-dao/only-boost/commit/670313c552e59646b00a7540d54b444f2228c3a5) by calculating optimal rebalance values before withdrawing.

## [M-01] CRV claimed as an extraRewardToken will be stuck in Strategy

When rewards are harvested via the strategy (either `OnlyBoost.sol` or `Strategy.sol`, depending on whether the optimizer is set or not), the goal is to claim all rewards and pass them along to the appropriate reward distributor.

The logic attempts to take into account that CRV will be the primary reward token, but may also be an extra reward token. For efficiency, we simply tally the total amount of CRV across both claims and deposit it into the reward distributor at the end of the function.

Let's look at the logic of `_claimExtraRewards()` to see the issue with how this is implemented...

```solidity
function _claimExtraRewards(address gauge, address rewardDistributor)
    internal
    virtual
    returns (uint256 _rewardTokenClaimed)
{
    /// If the gauge doesn't support extra rewards, skip.
    if (lGaugeType[gauge] > 0) return 0;

    // Cache the reward tokens and their balance before locker
    address[8] memory extraRewardTokens;
    uint256[8] memory snapshotLockerRewardBalances;

    uint8 i;
    address extraRewardToken;
    /// There can be up to 8 extra reward tokens.
    for (i; i < 8;) {
        /// Get extra reward token address.
        extraRewardToken = ILiquidityGauge(gauge).reward_tokens(i);
        if (extraRewardToken == address(0)) break;

        // Add the reward token address on the array
        extraRewardTokens[i] = extraRewardToken;
        // Add the reward token balance ot the locker on the array
        snapshotLockerRewardBalances[i] = ERC20(extraRewardToken).balanceOf(address(locker));

        unchecked {
            ++i;
        }
    }

    /// There's two ways to claim extra rewards:
    /// 1. Call claim_rewards on the gauge with the strategy as receiver.
    /// 2. Call claim_rewards on the gauge with the locker as receiver, then transfer the rewards from the locker to the strategy.
    /// 1 is not supported by all gauges, so we try to call it first, and if it fails, we fallback to 2.
    (bool isRewardReceived,) = locker.execute(
        gauge, 0, abi.encodeWithSignature("claim_rewards(address,address)", address(locker), address(this))
    );

    if (!isRewardReceived) {
        ILiquidityGauge(gauge).claim_rewards(address(locker));
    }

    for (i = 0; i < 8;) {
        extraRewardToken = extraRewardTokens[i];
        if (extraRewardToken == address(0)) break;
        uint256 claimed;
        if (!isRewardReceived) {
            claimed = ERC20(extraRewardToken).balanceOf(address(locker)) - snapshotLockerRewardBalances[i];
            if (claimed != 0) {
                // Transfer the freshly rewards from the locker to this contract.
                _transferFromLocker(extraRewardToken, address(this), claimed);
            }
        }

        if (extraRewardToken == rewardToken) {
            _rewardTokenClaimed += claimed;
        } else {
            claimed = ERC20(extraRewardToken).balanceOf(address(this));
            if (claimed != 0) {
                // Distribute the extra reward token.
                ILiquidityGauge(rewardDistributor).deposit_reward_token(extraRewardToken, claimed);
            }
        }

        unchecked {
            ++i;
        }
    }
}
```
- First, we snapshot the balance of all reward tokens in the locker before calling `claim_rewards()`.
- Then we call `claim_rewards()`. We first attempt to call it so that the rewards will be sent directly to the Strategy. If that fails, we use an alternate function signature that will send the funds to the locker.
- In the event that we need to use the second function, we capture the difference between the current balance and the prior balance snapshot, and send that amount from the locker to the strategy.
- If the token is not CRV, we then deposit the full balance into the reward distributor.
- If the token is CRV, we increment the amount to send at the end of the function call by `claimed`.

However, the problem lies in that `claimed` will only be set if the first `claim_rewards()` call fails. Otherwise, we skip the logic for setting `claimed`, and thus will increment the amount claimed by 0.

These funds will not be included in the deposit to the reward distributor, and will end up stuck in the Strategy instead.

### Proof of Concept

The following POC sets up the protocol on a forked mainnet instance, using the existing [crvs-FRAX gauge](https://etherscan.io/address/0x62B8DA8f1546a092500c457452fC2d45fa1777c4) as an example. It shows that after depositing tokens and claiming the non-extra CRV, we can then attempt to claim our extra tokens. After the second call, the additional CRV will end up in the Strategy, instead of being sent to the reward distributor where it belongs.

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.19;

import "forge-std/Test.sol";

import "src/CRVStrategy.sol";
import "solady/utils/LibClone.sol";
import {Vault} from "src/staking/Vault.sol";
import {IBooster} from "src/interfaces/IBooster.sol";
import {ISDLiquidityGauge, IGaugeController, PoolFactory, CRVPoolFactory} from "src/factory/curve/CRVPoolFactory.sol";

contract CRVExtraRewardsTest is Test {
    Vault vaultImplementation;
    CRVPoolFactory poolFactory;

    CRVStrategy strategy;
    CRVStrategy implementation;

    uint256 public pid = 252;
    ERC20 public token = ERC20(0xfEF79304C80A694dFd9e603D624567D470e1a0e7);
    address public gauge = 0x62B8DA8f1546a092500c457452fC2d45fa1777c4;

    address[] public extraRewardTokens;

    address public constant BOOSTER = address(0xF403C135812408BFbE8713b5A23a04b3D48AAE31);

    IGaugeController public constant GAUGE_CONTROLLER = IGaugeController(0x2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB);

    address public constant VE_CRV = 0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2;
    address public constant MINTER = 0xd061D61a4d941c39E5453435B6345Dc261C2fcE0;
    address public constant SD_VOTER_PROXY = 0x52f541764E6e90eeBc5c21Ff570De0e2D63766B6;
    ILocker public locker = ILocker(SD_VOTER_PROXY);
    address public constant REWARD_TOKEN = address(0xD533a949740bb3306d119CC777fa900bA034cd52);
    address public constant gaugeImplementation = address(0x3Dc56D46F0Bd13655EfB29594a2e44534c453BF9);

    function setUp() public {
        vm.createSelectFork("https://eth.llamarpc.com");

        /// Deploy Strategy
        implementation = new CRVStrategy(address(this), SD_VOTER_PROXY, VE_CRV, REWARD_TOKEN, MINTER);
        address _proxy = LibClone.deployERC1967(address(implementation));
        strategy = CRVStrategy(payable(_proxy));
        strategy.initialize(address(this));

        // Give strategy roles from depositor to new strategy
        vm.prank(locker.governance());
        locker.setStrategy(payable(address(strategy)));

        vaultImplementation = new Vault();
        poolFactory = new CRVPoolFactory(
            address(strategy),
            REWARD_TOKEN,
            address(vaultImplementation),
            gaugeImplementation
        );

        strategy.setFactory(address(poolFactory));
    }

    function testZach__CRVExtra() public {
        (address vault, address rewardDist) = poolFactory.create(0x62B8DA8f1546a092500c457452fC2d45fa1777c4);

        // confirm that CRV is a reward token based on the info grabbed from the gauge
        assert(REWARD_TOKEN == ILiquidityGauge(rewardDist).reward_tokens(1));

        uint amount = 100e18;
        deal(address(token), address(this), amount);
        ERC20(address(token)).approve(vault, amount);
        Vault(vault).deposit(address(token), amount, true);

        /// Then skip weeks to harvest SD.
        skip(2 weeks);

        // Claim all the CRV from the gauge (not via extra reward tokens)
        strategy.harvest(address(token), false, false, false);
        console2.log("harvesting native CRV (not extra reward token)...");

        // All the CRV so far is in the reward distributor
        uint rewardDistBalance = ERC20(REWARD_TOKEN).balanceOf(rewardDist);
        uint strategyBalance = ERC20(REWARD_TOKEN).balanceOf(address(strategy));
        console2.log("- reward dist CRV balance: ", rewardDistBalance);
        console2.log("- strategy CRV balance: ", strategyBalance);

        // Claim the CRV from the extra
        strategy.harvest(address(token), false, true, false);
        console2.log("\n  harvesting again to get only the extra rewards CRV...");

        // None of the new CRV claimed flowed to reward distributor, it's stuck in Strategy
        console2.log("- increase in reward dist CRV balance: ", ERC20(REWARD_TOKEN).balanceOf(rewardDist) - rewardDistBalance);
        console2.log("- increase in strategy CRV balance: ", ERC20(REWARD_TOKEN).balanceOf(address(strategy)) - strategyBalance);
    }
}
```
```
Logs:
  harvesting native CRV (not extra reward token)...
  - reward dist CRV balance:  196691120093108400
  - strategy CRV balance:  0

  harvesting again to get only the extra rewards CRV...
  - increase in reward dist CRV balance:  0
  - increase in strategy CRV balance:  15879878192329000
```

### Recommendation

In the event that the first `claim_rewards()` call succeeds, we should take the difference in CRV balance of the Strategy itself in order to increment `_rewardTokenClaimed` appropriately.

### Review

Fixed as recommended in commit [42f2b4bfb27d77f9a99cb548c0fca7316a74c0a0](https://github.com/stake-dao/only-boost/commit/42f2b4bfb27d77f9a99cb548c0fca7316a74c0a0).


## [M-02] Balancing mechanism will often be imprecise

This is a catch all issue to discuss the areas in which the formulas used for balancing, as well as the implementation realities to lower gas fees, cause the optimizer to misallocate funds between Convex and StakeDAO.

It is clear that the purpose of the protocol is that, on the whole, users will at least be better off than if they simply allocated directly to Convex, and this is largely achieved. However, there are (a) a large number of situations in which funds are overallocated to Convex that would provide a better return on StakeDAO and (b) a small number of situations in which funds would be more profitable on Convex directly.

### Deposits

When funds are deposited, based on the final step of the whitepaper, we assume that `S ~= S0`, meaning that we don't take the current deposit into account when calculating the optimal StakeDAO balance. This calculation is performed based on the current Convex balance, assuming the relative size of the current deposit is approximately zero.

After we calculate the optimal StakeDAO amount, we allocate all additional funds that are a part of the deposit in excess of this amount to Convex.

The result is that, if we perform a number of small deposits, funds will be split appropriately between StakeDAO and Convex. If we perform one large deposit for the same amount, funds will overallocated to Convex.

Since vault's implement logic to encourage users to batch their transactions together to make larger, more gas efficient deposits, this will tend towards creating a dynamic in which Convex has more allocation than it should.

### Withdrawals

In the whitepaper, it explains that:

> Withdrawals are performed directly from the strategy, first withdrawing from Convex until strategy balance equals StakeDAO’s target balance, and then from StakeDAO.

However, the implementation instead checks the balances of StakeDAO and of our Convex fallback. The full withdrawal is taken from whichever has a larger balance if possible. If there isn't sufficient liquidity, the remainder will be taken from the smaller balance.

This causes two problems:

1) The balance measured does not provide any insight into where the withdrawal should be taken. For example, Convex may natively hold so much of an LP token that it's boost is tiny, but since the fallback contains a small amount of funds, withdrawals would be taken from StakeDAO instead. This would cause use to overallocate to Convex.

2) Taking the full withdrawal from the larger balance completely ignores the optimal point when we should be stopping. We have a formula implemented to calculate the optimal StakeDAO amount, but this is ignored for these purposes. As a result, we can withdraw all of either StakeDAO or Convex when we should be performing a more balanced withdrawal. This can cause us to end up overallocated in either StakeDAO or Convex, depending which has the larger balance when the function is called.

### Caching

Caching is implemented in such a way that if a value is calculated and suggests an optimal StakeDAO balance, it is saved for 7 days and used as long as we haven't deposited sufficient funds into the StakeDAO locker to reach that balance.

This is intentionally designed to avoid the risk that Convex could manipulate the cache in their favor, and therefore caching can only be used for deposits that go wholly to StakeDAO.

However, it is still possible that variables change in such a way (veCRV balances, pool token holdings, etc) that StakeDAO's optimal balance decreases over the 7 days, but it is still allocated the full amount that was previously calculated.

This can cause us to end up overallocated into StakeDAO.

### Recommendation

Each of these decisions is a trade off of gas efficiency vs balance of the pools. None appears to be a security risk (since it's a zero sum game between Convex and StakeDAO that doesn't leak value), but all of them will decrease the value of the protocol to users.

As it currently stands, the protocol is likely to have large swings in allocation of the funds between the two protocols, and the swings may be controllable by outside users, and somewhat unpredictable in nature.

It is recommended to ensure that the protocol's assumptions are more consistent (ie lean towards Convex more predictably) and that the `rebalance()` function successfully rebalances (see other issue) so that it can be used to recover when there is drift due to the above issues.

### Review

This isn't wasn't fixed directly, but because `rebalance()` was fixed (see H-01), it can now be used to stop any of the other issues from causing too much drift.

## [M-03] Optimizer will misallocate when StakeDAO is above full boost

On Page 5 of the whitepaper, it says:

> We can assume that when this balance is reached for a given gauge, neither Convex nor Stake DAO have maximum boost, which enables us to get rid of the min formula.

The `min` in the formula is intended to cap the boost at 2.5x. If the proportion of veCRV held by a user is greater than their proportion of pool tokens, they will be capped at 2.5x, rather than further increasing the boost.

One example of when this could happen is if both pools have full 2.5x boosts. This example was pointed out in the last audit, and a fix was added to manually send funds to Convex if both pools had maximum boosts.

However, upon further reflection, this fix is not sufficient.

We can simplify the issue with the understanding that, when the `min` is removed from the formula, it allows the formula's perceived boost for a protocol to exceed 2.5x. For example, if StakeDAO holds `10%` of veCRV and only holds `1%` of a given pool, assuming the pool has 100 tokens for simplicity, the boost will be calculated as:
```python
boost = ((0.4 * 1) + (0.6 * 100 * 10%)) / 0.4 = 16x
```
If the min was included, it would have been capped at 2.5x, but instead is allowed to reach 16x. As a result, when the Optimizer calculates the ideal allocation, it will favor this pool more aggressively than it should.

The issue pointed out in the previous audit examines when such an example is matched with a Convex pool at full boost. In this case, the 2.5x from Convex is identical to the 2.5x from StakeDAO, and the Optimizer misattributing StakeDAO a 16x boost would cause funds to flow there, even though the ideal would be allocate to Convex due to the incentives.

But, as we can see from this example, the same issue holds when Convex reaches 2.49x boost, and lower. In fact, calculating precisely, we find the breakeven point. The returns from each protocol are as follows:
```python
convex _return= convex_boost * (1 - 0.17 + 0.05)
sd_return = sd_boost * (1 - 0.16)
```
To calculate the breakeven point for `convex_boost` for when `sd_boost == 2.5x`, we can solve and plug in:
```python
convex_boost * 0.88 == 2.5 * 0.84
convex_boost = 2.386
```
Therefore, in any situation in which Convex has a boost greater than 2.386, it is preferable over StakeDAO with full boost. In these cases, Convex should receive the full deposit.

The same issue exists when Convex is below 2.386x boost, because the optimal balance for StakeDAO will be set too high, so more funds will flow to StakeDAO than should.

### Recommendation

The issue that the Optimizer assumes that boosts can get arbitrarily high can't be accurately solved by intercepting the request for special circumstances beforehand, because any situation in which StakeDAO has more than 2.5x boost will create an inaccurate optimal value.

Instead, the `computeOptimalDepositAmount()` formula should take the minimum amounts into account when performing its calculations to get a more accurate response.

### Review

Acknowledged.


## [M-04] Curve gauges with 7+ extra reward tokens cannot be integrated

When the PoolFactory creates new reward distributors, we begin by manually adding CRV and SDT as reward tokens. We then iterate through the Curve gauge's reward tokens and add each of those to the StakeDAO reward distributor.

```solidity
/// @notice Add extra reward tokens to the reward distributor.
/// @param _gauge Address of the liquidity gauge.
function _addExtraRewards(address _gauge) internal virtual {
    /// Check if the gauge supports extra rewards.
    /// This function is not supported on all gauges, depending on when they were deployed.
    bytes memory data = abi.encodeWithSignature("reward_tokens(uint256)", 0);

    /// Hence the call to the function is wrapped in a try catch.
    (bool success,) = _gauge.call(data);
    if (!success) {
        /// If it fails, we set the LGtype to 1 to indicate that the gauge doesn't support extra rewards.
        /// So the harvest would skip the extra rewards.
        strategy.setLGtype(_gauge, 1);

        return;
    }

    /// Loop through the extra reward tokens.
    /// 8 is the maximum number of extra reward tokens supported by the gauges.
    for (uint8 i = 0; i < 8;) {
        /// Get the extra reward token address.
        address _extraRewardToken = ISDLiquidityGauge(_gauge).reward_tokens(i);

        /// If the address is 0, it means there are no more extra reward tokens.
        if (_extraRewardToken == address(0)) break;

        /// Performs checks on the extra reward token.
        /// Checks like if the token is also an lp token that can be staked in the locker, these tokens are not supported.
        if (_isValidToken(_extraRewardToken)) {
            /// Then we add the extra reward token to the reward distributor through the strategy.
            strategy.addRewardToken(_gauge, _extraRewardToken);
        }

        unchecked {
            ++i;
        }
    }
}
```

StakeDAO's reward distributor is a fork of Curve's gauges. Both implementations have a `MAX_REWARDS` value of 8, meaning that more than 8 extra reward tokens cannot be added to a gauge.

However, the StakeDAO reward distributor attempts to copy over all of the Curve extra rewards, as well as adding CRV and SDT.

In the event that the Curve gauge has 7 or 8 extra rewards, this will push the StakeDAO gauge over the limit of 8, and the creation will revert.

### Proof of Concept

We will test this using the following Curve gauge: [0x7ca5b0a2910B33e9759DC7dDB0413949071D7575](https://etherscan.io/address/0x7ca5b0a2910B33e9759DC7dDB0413949071D7575), overwriting it with additional reward tokens.

We can preserve its underlying `lp_token` value while overwriting the reward tokens as follows:
```solidity
contract GaugeWithMaxRewardTokens {
    function lp_token() external view returns (address) {
        return 0x845838DF265Dcd2c412A1Dc9e959c7d08537f8a2;
    }

    function reward_tokens(uint256 i) external view returns (address) {
        if (i == 0) {
            return 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
        } else if (i == 1) {
            return 0xdAC17F958D2ee523a2206206994597C13D831ec7;
        } else if (i == 2) {
            return 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
        } else if (i == 3) {
            return 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984;
        } else if (i == 4) {
            return 0x514910771AF9Ca656af840dff83E8264EcF986CA;
        } else if (i == 5) {
            return 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
        } else if (i == 6) {
            return 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
        } else if (i == 7) {
            return 0xF17A3fE536F8F7847F1385ec1bC967b2Ca9caE8D;
        } else {
            revert("NOT POSSILBE");
        }
    }
}
```
We can etch this contract over the existing gauge and try to create a pool with it as follows:
```solidity
function testZach__gauge_with_max_fails() public {
    address gauge_to_test = 0x7ca5b0a2910B33e9759DC7dDB0413949071D7575;
    address gauge_with_max = address(new GaugeWithMaxRewardTokens());
    vm.etch(gauge_to_test, gauge_with_max.code);
    (address x, address y) = poolFactory.create(gauge_to_test);
}
```
The result is that the creation will revert when it attempts to add the 7th reward token, as that pushes it over the limit of 8.

### Recommendation

The forked reward distributor contract should be adjusted to set `MAX_REWARDS = 10` in order to integrate properly.

### Review

Fixed in Liquidity Gauge V4 in commit [a7fc33d1a5351fe8010230d016bb058c3de2b927](https://github.com/stake-dao/only-boost/commit/a7fc33d1a5351fe8010230d016bb058c3de2b927).


## [M-05] Deployment script mismatches gauges and reward distributors

In Deployment.s.sol, a list of gauges (Curve) and reward distributors (StakeDAO) are provided to migrate.

The gauge list is 162 elements long, but the reward distributor list is only 160 elements long, missing the corresponding reward distributors to the final two gauges.

The match between these two lists is crucial, as funds will be migrated and permissions granted accordingly.

### Recommendation

Beyond adding the two missing reward distributors, I recommend adding checks to the deployment script to ensure the two lists are equal length and the addresses at each index are intended to correspond with each other:
```diff
+ require(rewardDistributors.length == gauges.length);
  for (uint256 i = 0; i < rewardDistributors.length; i++) {
+     IStrategy oldStrategy = IStrategy(locker.governance());
+     require(oldStrategy.multigauges(gauges[i]) == rewardDistributors[i]);
      ...
  }
```

### Review

Fixed as recommended in commit [315fc02e6b9b97698b1b24f2e853151513590707](https://github.com/stake-dao/only-boost/commit/315fc02e6b9b97698b1b24f2e853151513590707).


## [L-01] Optimizer rounds negative feeDiff values to zero

In the optimal deposit formula in Optimizer.sol, we calculate the `feeDiff` between Convex and StakeDAO. `feeDiff` represents how much more profitable each dollar earned in Convex is than StakeDAO, taking into account fees and incentives.

Since StakeDAO's fee is 16% and Convex is 17%, and we are only taking into account Convex incentives, the possible range for `feeDiff` is `-1 <= feeDiff <= inf`.

When this value is calculated, we do the following:
```solidity
uint256 feeDiff = boost + stakeDaoTotalFee > convexTotalFee ? stakeDaoTotalFee + boost - convexTotalFee : 0;
```
In short, if `boost` (Convex incentives) is greater than the gap in fees, we perform the calculation. However, if `boost` is not sufficient to cover the gap in fees, we default to zero.

This creates a loss of precision in the formula for situations when Convex's incentive is less than 1%, which is due to happen in the coming years as their inflation rate slows down.

### Recommendation

To increase the precision, allow `feeDiff` to represent a negative number as low as `-1e16` and use that value in the computation.

### Review

Acknowledged.


## [L-02] Fallback & vault fees must remain at zero for Optimizer to work as intended

In the OnlyBoost whitepaper, it's explained that fees on Convex rewards must be set to zero in order to justify the optimizations provided by the protocol.

> As we said earlier, it is a very nice increase but doesn't justify an additional performance fee on top of Convex, that's why it's important that this strategy doesn't charge fees for the share of deposits that go through Convex.

However, the protocol does implement a fee layer on the funds returned by Convex. As we can see in the ConvexImplementation.sol#claim() function:
```solidity
protocolFees = _chargeProtocolFees(rewardTokenAmount);
```
```solidity
/// @notice Internal function to charge protocol fees from `rewardToken` claimed by the locker.
function _chargeProtocolFees(uint256 _amount) internal view returns (uint256 _feeAccrued) {
    if (_amount == 0) return 0;

    uint256 protocolFeesPercent = factory().protocolFeesPercent();
    if (protocolFeesPercent == 0) return 0;

    _feeAccrued = _amount.mulDiv(protocolFeesPercent, DENOMINATOR);
}
```
While these fees are kept separate from the StakeDAO fees (which allows settings to be set in accordance with the whitepaper), it is important that these fees be set to exactly `0` in order for the optimizations performed by the protocol to work as expected.

Note that a similar issue exists with the `withdrawalFee` set on all vaults that use the old implementation. Taking any fees at this layer will take from both Convex and StakeDAO rewards, and will therefore break the intended optimization.

### Recommendation

Be sure to keep the fees on all Convex fallbacks, as well as all old vaults, set to `0` for the protocol to work as expected.

### Review

Acknowledged.


## [L-03] `setGauge()` and `setRewardDistributor()` should revoke old approvals

When `setGauge()` or `setRewardDistributor()` is called, we set the local mappings, and then approve the corresponding token for transfers.

In `setGauge()`, we approve the Curve gauge to spend the LP token from the locker:
```solidity
function setGauge(address token, address gauge) external onlyGovernanceOrFactory {
    if (token == address(0)) revert ADDRESS_NULL();
    if (gauge == address(0)) revert ADDRESS_NULL();

    gauges[token] = gauge;

    /// Approve trough the locker.
    locker.safeExecute(token, 0, abi.encodeWithSignature("approve(address,uint256)", gauge, 0));
    locker.safeExecute(token, 0, abi.encodeWithSignature("approve(address,uint256)", gauge, type(uint256).max));
}
```
In `setRewardDistributor()`, we approve the reward distributor to spend CRV:
```solidity
function setRewardDistributor(address gauge, address rewardDistributor) external onlyGovernanceOrFactory {
    if (gauge == address(0) || rewardDistributor == address(0)) revert ADDRESS_NULL();
    rewardDistributors[gauge] = rewardDistributor;

    /// Approve the rewardDistributor to spend token.
    SafeTransferLib.safeApproveWithRetry(rewardToken, rewardDistributor, type(uint256).max);
}
```
It would be safer to explicitly revoke old approvals to ensure that there are no lingering approvals to old gauges.

### Recommendation

```diff
function setGauge(address token, address gauge) external onlyGovernanceOrFactory {
    if (token == address(0)) revert ADDRESS_NULL();
    if (gauge == address(0)) revert ADDRESS_NULL();

+   address oldGauge = gauges[token];
+   if (oldGauge != address(0)) {
+     locker.safeExecute(token, 0, abi.encodeWithSignature("approve(address,uint256)", oldGauge, 0));
+   }

    gauges[token] = gauge;

    /// Approve trough the locker.
    locker.safeExecute(token, 0, abi.encodeWithSignature("approve(address,uint256)", gauge, 0));
    locker.safeExecute(token, 0, abi.encodeWithSignature("approve(address,uint256)", gauge, type(uint256).max));
}
```
```diff
function setRewardDistributor(address gauge, address rewardDistributor) external onlyGovernanceOrFactory {
    if (gauge == address(0) || rewardDistributor == address(0)) revert ADDRESS_NULL();

+   address oldRewardDistributor = rewardDistributors[gauge];
+   if (oldRewardDistributor != address(0)) {
+     SafeTransferLib.safeApprove(rewardToken, rewardDistributor, 0);
+   }

    rewardDistributors[gauge] = rewardDistributor;

    /// Approve the rewardDistributor to spend token.
    SafeTransferLib.safeApproveWithRetry(rewardToken, rewardDistributor, type(uint256).max);
}
```

### Review

Fixed as recommended in commit [bfea1a1247100b11ce1b1455eba178a706d64b96](https://github.com/stake-dao/only-boost/commit/bfea1a1247100b11ce1b1455eba178a706d64b96).


## [L-04] `_isValidToken()` check should not allow SDT

When a new vault and reward distributor are created using the PoolFactory, we add the reward tokens to the new StakeDAO reard distributor as follows:
1) We manually add CRV and SDT as reward tokens.
2) We iterate through all extra reward tokens from the Curve gauge, and if they pass the `_isValidToken()` check, we add them as reward tokens.

```solidity
if (_isValidToken(_extraRewardToken)) {
    /// Then we add the extra reward token to the reward distributor through the strategy.
    strategy.addRewardToken(_gauge, _extraRewardToken);
}
```

The `_isValidToken()` check returns `false` for CRV, as well as some other situations that should not be allowed:

```solidity
function _isValidToken(address _token) internal view override returns (bool) {
    /// We can't add the reward token as extra reward.
    /// We can't add special pools like the Ve Funder.
    if (_token == rewardToken || _token == VE_FUNDER) return false;

    /// If the token is available as an inflation receiver, it's not valid.
    try GAUGE_CONTROLLER.gauge_types(_token) {
        return false;
    } catch {
        return true;
    }
}
```

However, it will return `true` for `SDT`.

This means, in the event that `SDT` is ever an extra reward token for a Curve gauge, we will attempt to call `strategy.addRewardToken()` with it.

However, since `SDT` has already been added manually to the list, this second attempt to add it will trigger the assertion on the reward distributor that the `distributor` for the given token has not yet been set:
```python
@external
def add_reward(_reward_token: address, _distributor: address):
    """
    @notice Set the active reward contract
    """
    assert msg.sender == self.admin  # dev: only owner

    reward_count: uint256 = self.reward_count
    assert reward_count < MAX_REWARDS
    assert self.reward_data[_reward_token].distributor == ZERO_ADDRESS

    self.reward_data[_reward_token].distributor = _distributor
    self.reward_tokens[reward_count] = _reward_token
    self.reward_count = reward_count + 1
```
This will cause the pool creation to revert, and there will be no way to create a vault for this gauge.

### Proof of Concept

The following contract can be etched over an existing pool in order to maintain the correct respond to `lp_token()` but return `SDT` as a reward token:
```solidity
contract GaugeWithSDTExtraReward {
    function lp_token() external view returns (address) {
        return 0x845838DF265Dcd2c412A1Dc9e959c7d08537f8a2;
    }

    function reward_tokens(uint i) external view returns (address) {
        if (i == 0) {
            return 0x73968b9a57c6E53d41345FD57a6E6ae27d6CDB2F;
        } else {
            return address(0);
        }
    }
}
```
The trace of the following test will show that the call reverts when `add_reward()` is called for SDT the second time, due to the failure outlined above:
```solidity
function testZach__gauge_with_sdt_fails() public {
    address gauge_to_test = 0x7ca5b0a2910B33e9759DC7dDB0413949071D7575;
    address gauge_with_max = address(new GaugeWithSDTExtraReward());
    vm.etch(gauge_to_test, gauge_with_max.code);
    poolFactory.create(gauge_to_test);
}
```

### Recommendation

[Note: This recommendation is not finalized. The recommendation below would cause a problem because the distributor would still be set for SDT_DISTRIBUTOR instead of strategy, so the deposits to the reward distributor would fail. Let's discuss if there's a better solution or if we're certain the situation will never happen, and this issue can be removed.]

Ensure that `_isValidToken()` returns false when `SDT` is passed.

```diff
+   address constant SDT = 0x73968b9a57c6E53d41345FD57a6E6ae27d6CDB2F;

    /// @inheritdoc PoolFactory
    function _isValidToken(address _token) internal view override returns (bool) {
        /// We can't add the reward token as extra reward.
+       /// We can't add SDT as extra reward because it's already added
        /// We can't add special pools like the Ve Funder.
-       if (_token == rewardToken || _token == VE_FUNDER) return false;
+       if (_token == rewardToken || _token == SDT || _token == VE_FUNDER) return false;
        ...
```

### Review

Fixed as recommended in commit [13a244aba97300ef4e707b6401bc4e8124c59048](https://github.com/stake-dao/only-boost/commit/13a244aba97300ef4e707b6401bc4e8124c59048).

Note that, in this fix, gauges that have SDT as a reward token will have the reward distributed by the `SDT_DISTRIBUTOR` instead of the strategy. The StakeDAO team has acknowledged this, and will ensure that if users want to incentivize with SDT, they should do it through StakeDAO.


## [L-05] Reward Distributor implementation uses vulnerable Vyper version

The reward distributor implementation is currently set to use Vyper 0.2.16. This version contains [a vulnerability that prevents reentrancy locks from working properly](https://github.com/vyperlang/vyper/security/advisories/GHSA-5824-cm3x-3c38).

The contract uses `@nonreentrant('lock')` to lock a number of functions. Because of the nature of the vulnerability, each of these locks will lock the specific function from being reentered, but will not prevent a reentrance into another function in the contract.

As an example, if a user was able to gain control flow in the middle of function execution, they could call `claim_rewards()` and, before the latest checkpoint was updated, reenter into `claim_rewards_for()` with the same receiver address and collect the rewards again.

Upon quick review, it appears that the current version is not vulnerable to this attack, because there does not appear to be a vulnerable place where control flow is passed back to the caller mid-execution. However, sufficient time was not spent on this contract (given that it is out of scope) to be sure of that assessment. Further, if Curve were to add a gauge with an extra reward token that contained a callback, this vulnerability would emerge.

### Recommendation

For safety, it is recommended to upgrade the implementation to the latest Vyper version (0.3.10) before deploying.

In order to make this change, the following upgrades will need to be made:
- `ZERO_ADDRESS` should be changed to`empty(address)`
- `shift(x, y)` should be changed to `x >> y` or `x << y`
- `MAX_UINT256` should be changed to `max_value(uint256)`

While there don't appear to be any other breaking changes [between 0.2.16 and 0.3.10](https://docs.vyperlang.org/en/stable/release-notes.html#v0-2-16) that could cause problems, it is also recommended to include a standard suite of tests for the contract to ensure it continues to behave as expected.

### Review

Fixed as recommended in commit [a7fc33d1a5351fe8010230d016bb058c3de2b927](https://github.com/stake-dao/only-boost/commit/a7fc33d1a5351fe8010230d016bb058c3de2b927) by upgrading to Liquidity Gauge V4, which uses Vyper 0.3.10 and makes the necessary updates to the source code for it to compile.

## [I-01] Strong trust assumption that Convex will act in good faith

There are a number of trust assumptions in the protocol that assume that Convex will act in good faith. Specifically, Convex has control over data returned from various functions which could be altered to influence the behavior of the strategy.

For example:

1) When claiming extra reward tokens from Convex, we assume that the data returned from `baseRewardPool.extraRewards(i)` is accurate. Convex could clear the list of extra reward tokens from the `baseRewardPool`, call `claim()` on the StakeDAO contract (skipping the extra rewards), and then re-add the tokens to the list — effectively skirting around paying these rewards to StakeDAO.

2) We assume that `ERC20(gauge).balanceOf(VOTER_PROXY_CONVEX)` will accurately reflect the amount of gauge token held by Convex. However, there may be ways for them to temporarily alter this value to throw off the optimization.

3) There are some quirks in the balancing of deposits and withdrawals between Convex and StakeDAO (discussed in other issues). These quirks could be used to consistently move funds towards a high allocation on Convex and away from StakeDAO.

### Recommendation

Set up monitoring solutions to ensure the protocol is behaving as expected, with flags to warn you of any of the scenarios that might point to Convex manipulating the strategy.

### Review

Acknowledged.
