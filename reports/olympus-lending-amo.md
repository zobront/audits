<table>
    <tr><th></th><th></th></tr>
    <tr>
        <td><img src="https://media-exp1.licdn.com/dms/image/C4E0BAQGsUEaZCJtT-w/company-logo_200_200/0/1625861473301?e=2147483647&v=beta&t=y8nFNaFXa7nkrgNV8-8giEb0m5s9cYOEwHSMJCC4a3s" width="250" height="250" /></td>
        <td>
            <h1>OlympusDAO Audit Report</h1>
            <h2>Lending AMO & SiloAMO</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: June 19 to 23, 2023</p>
        </td>
    </tr>
</table>

# About **Olympus' Lending AMO**

The Lending AMO allows Olympus to algorithmically mint and burn OHM to help external lending markets maintain an optimal OHM supply. This has the benefit to users of providing a competitive borrowable asset and predictable borrow rates, while providing Olympus with efficient supply expansion, more diversified backing of circulating OHM, and revenue via interest accumulation.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

[PR #131](https://github.com/OlympusDAO/bophades/pull/131) of the [OlympusDAO/bophades](https://github.com/OlympusDAO/bophades) repository was audited.

The following contracts were in scope:
- src/modules/LENDR/LENDR.v1.sol
- src/modules/LENDR/OlympusLender.sol
- src/policies/LendingAMOs/SiloAMO.sol

After completion of the fixes, the [58d04cbd193c957924c14d20fd3889a99955b8c2](https://github.com/OlympusDAO/bophades/pull/131/commits/58d04cbd193c957924c14d20fd3889a99955b8c2) commit of PR #131 was reviewed.

# Summary of Findings

|  Identifier  | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [H-01] | SiloAMO can be forced to fund reduced interest rates by manipulating utilization | High | ✓ |
| [H-02] | If AMO becomes primary depositor of Silo, user can force withdrawals to get inflated interest rates | High | ✓ |
| [H-03] | Yield cannot be harvested because wrong token is passed to Incentives Controller | High | ✓ |
| [H-04] | AMO model opens up OHM treasury to increased risk | High | ✓ |
| [M-01] | ohmDeployed will become inaccurate if circulatingOhmBurned is used | Medium | ✓ |
| [M-02] | SiloAMO uses outdated InterestRateModel | Medium | ✓ |
| [M-03] | If MINTR is paused, SiloAMO will not be able to unwind its position | Medium | ✓ |
| [L-01] | Yield can only be withdrawn to the admin address, not the treasury | Low | ✓ |
| [L-02] | Admin has unlimited power to mint new OHM | Low |  |
| [L-03] | `update()` can be DOS'd by frontrunning with dust deposits and withdrawals | Low | ✓ |
| [I-01] | MINTR.decreaseMintApproval permission is set, but is never used | Informational | ✓ |
| [I-02] | Emergency Unwind can be performed in one transaction | Informational | ✓ |
| [I-03] | Comment in `getTargetDeploymentAmount()` specifies wrong decimals | Informational | ✓ |

# Detailed Findings

## [H-01] SiloAMO can be forced to fund reduced interest rates by manipulating utilization

When `update()` is permissionlessly called on the SiloAMO, it decides whether to deposit or withdraw funds by comparing the `totalDeposits` to an "ideal" amount of deposits that is calculated by multiplying the `totalBorrows` by `uopt` (the optimal utilization rate set on the Silo).

```solidity
function _update() internal {
    // Accrue interest on Silo
    ISilo(market).accrueInterest(address(OHM));

    // Get current total deposits and target total deposits
    ISilo.AssetStorage memory assetStorage = ISilo(market).assetStorage(address(OHM));
    uint256 currentDeployment = getUnderlyingOhmBalance();
    uint256 totalDeposits = assetStorage.totalDeposits;
    uint256 targetDeploymentAmount = getTargetDeploymentAmount();

    if (targetDeploymentAmount < totalDeposits) {
        // If the target deployment amount is less than the total deposits, then we need to withdraw the difference
        uint256 amountToWithdraw = totalDeposits - targetDeploymentAmount;
        if (amountToWithdraw > currentDeployment) amountToWithdraw = currentDeployment;

        if (amountToWithdraw > 0) _withdraw(amountToWithdraw);
    } else if (targetDeploymentAmount > totalDeposits) {
        // If the target deployment amount is greater than the total deposits, then we need to deposit the difference
        uint256 amountToDeposit = targetDeploymentAmount - totalDeposits;
        if (amountToDeposit > maximumToDeploy - ohmDeployed)
            amountToDeposit = maximumToDeploy - ohmDeployed;

        if (amountToDeposit > 0) _deposit(amountToDeposit);
    }
}
```
If a user is able to manipulate `totalBorrows` up, it can bait the SiloAMO into depositing substantially more funds into the Silo.

This is an issue, because `update()` can only be called once every `updateInterval` (currently set to 1 day in fork tests). This means that if a user is able to force SiloAMO to deposit additional funds (thus lowering the interest rate), the funds will remain in the Silo for at least one day.

In order to protect against this possibility, the SiloAMO checks if the interest rate timestamp has been updated in the current block. If it has, it does not allow `update()` to be called:
```solidity
ISilo.UtilizationData memory utilizationData = ISilo(market).utilizationData(address(OHM));
if (utilizationData.interestRateTimestamp == block.timestamp)
    revert AMO_UpdateReentrancyGuard(address(this));
```
While this successfully protects against flash loans, it does not protect against a similar attack that occurs with an attacker's own funds.

Here is a simple flow of what this might look like:
- An attacker deposits a large amount of WETH or XAI into the OHM Silo (or, with slightly more effort, deposit a smaller amount of WETH or XAI, borrow OHM, trade it for WETH or XAI, and use this pattern to create a leveraged borrow position)
- The block before `update()` is allowed to be called, they take a large borrow of OHM
- This increases the interest rate, but puts `totalDeposits` far below the optimal utilization rate
- The next block, they call `update()`, which causes SiloAMO to deposit a large amount of OHM
- Immediately after this transaction, the user repays their borrowed OHM, minimizing interest costs

The result is that the interest rates will be forced down for a full day. This attack can be repeated daily in order to keep the interest rate deflated.

### Proof of Concept

I've put together the following standalone fork test to model this situation. It can be dropped into your current test suite and run with the relevant interfaces imported and RPC_URL inserted.

```solidity
contract TestInterestRateManipulation is Test {
    using FullMath for uint256;

    ISilo silo = ISilo(0xf5ffabab8f9a6F4F6dE1f0dd6e0820f68657d7Db);
    IERC20 ohm = IERC20(0x64aa3364F17a4D01c6f1751Fd97C2BD3D7e7f1D5);
    IERC20 weth = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address shareCollToken = 0x907136B74abA7D5978341eBA903544134A66B065;
    IInterestRateModel model = IInterestRateModel(0x76074C0b66A480F7bc6AbDaA9643a7dc99e18314);
    address amo = makeAddr("policy");

    function testInterestRateManipulation() public {
        vm.createSelectFork("RPC_URL");
        deal(address(weth), address(this), 10_000e18);
        weth.approve(address(silo), 10_000e18);
        deal(shareCollToken, amo, 10_000e18);
        vm.startPrank(amo);
        IERC20(shareCollToken).approve(address(silo), 10_000e18);
        ohm.approve(address(silo), 100_000e9);
        vm.stopPrank();
        deal(address(ohm), address(this), 100_000e9);
        ohm.approve(address(silo), 100_000e9);
        deal(address(ohm), amo, 100_000e9);

        // the starting rate for the silo
        _update();
        console.log("Starting Rate: ", model.getCurrentInterestRate(address(silo), address(ohm), block.timestamp));

        // we make a large borrow, which pushes rates up but also baits the amo into depositing a large amount of OHM
        silo.deposit(address(weth), 10_000e18, false);
        (uint borrowAmt,) = silo.borrow(address(ohm), silo.liquidity(address(ohm)));
        console.log("Rate After OHM Borrow: ", model.getCurrentInterestRate(address(silo), address(ohm), block.timestamp));

        // wait one block so that update() is allowed to be called
        vm.warp(block.timestamp + 12);

        // now we force update()
        _update();
        console.log("Rate After Update: ", model.getCurrentInterestRate(address(silo), address(ohm), block.timestamp));

        // we immediately repay our borrow to minimize interest costs
        silo.repay(address(ohm), borrowAmt);
        vm.warp(block.timestamp + 12);
        console.log("Rate After Repayment: ", model.getCurrentInterestRate(address(silo), address(ohm), block.timestamp));

        // this reduced rate is now locked in for 1 day
    }

    function _update() internal {
        uint256 totalDeposits = silo.assetStorage(address(ohm)).totalDeposits;
        uint256 totalBorrowed = silo.utilizationData(address(ohm)).totalBorrowAmount;
        int256 optimalUtilizationPct = 0.5e18; // hardcoded what it is on the contract
        uint targetDeploymentAmount = totalBorrowed.mulDiv(1e18, uint256(optimalUtilizationPct));
        vm.prank(amo);
        if (totalDeposits < targetDeploymentAmount) {
            silo.deposit(address(ohm), targetDeploymentAmount - totalDeposits, false);
        } else if (totalDeposits > targetDeploymentAmount) {
            silo.withdraw(address(ohm), totalDeposits - targetDeploymentAmount, false);
        }
    }
}
```
```
Logs:
  Starting Rate:  70000385185008000 // 7% per year
  Rate After OHM Borrow:  1139999999984496000 // 114% per year
  Rate After Update:  140027777674272000 // 14% per year
  Rate After Repayment:  34097713619616000 // 3.4% per year
```
While the POC is written to assume that the attacker holds approximately $500k of WETH in the Silo, the attack is possible with a much smaller balance because of the ability for the attacker to take a leveraged position. They can do this by depositing WETH, borrowing OHM, trading the OHM for WETH which can be deposited, borrowing more OHM, etc. The amount of leverage that can be taken depends on the maximum LTV value, as follows:
```
0.9 LTV = 9x
0.85 LTV = 5.66x
0.8 LTV = 4x
0.75 LTV = 3x
0.7 LTV = 2.33x
0.6 LTV = 1.5x
```
This would allow an attacker to perform this attack with substantially less capital than might otherwise be expected.

Further, despite the capital requirements, the attack itself poses no additional risk to their funds. We can estimate the interest paid for the one block of the attack as:
```
45,000 OHM = $480,000 USD
$480,000 USD * 114% annual rate = $547,200 USD per year of interest
$547,200 USD / 365 days / 7200 blocks per day = $0.21
```

### Recommendation

This is a tricky problem, but I see three possible solutions, listed in order of my preference:

1) Impose bounds on the `update()` function to only operate when `uopt` is between `ulow` and `ucrit`. In the event that the utilization rate falls outside of these bounds, a manual call to `deposit()` or `withdraw()` will need to be made by the Olympus team to restart the AMO. Since the [Silo Interest Rate Curve](https://silopedia.silo.finance/interest-rates/how-is-interest-calculated) is very flat between these values, this will ensure that no major manipulation can be performed.

2) Adjust the system to be permissioned, with `update()` only callable by the `lendingamo_admin`. While this will remove a lot of the benefits of a permissionless system, combining it with the current checks that the Silo has not been adjusted in the current block, it will provide a strong defense against any tampering.

3) Implement a maximum `stepSize` percentage, which will only allow the AMO to nudge the Silo in the direction of equilibrium, rather than adjust it all the way to `uopt`. However, this has the downside of removing a lot of the incentive for a user to call `update()`, because they will need to call it daily for multiple days to adjust the rate fully, which most users won't be willing to do in order to get a preferred rate on a loan.

### Review

Initially fixed following the first recommendation in [4bce45602daa4ee49b1ef52acf6f88021d1390d7](https://github.com/OlympusDAO/bophades/commit/4bce45602daa4ee49b1ef52acf6f88021d1390d7).

However, during the fix review, it was uncovered that bounding the `util` within the `ulow` to `ucrit` range before the update would not guarantee such a bound after the update. [See the logic in this writeup for an explanation](https://gist.github.com/zobront/d4a1507b1872b29392ca7d598a6fd3f1).

This was fixed in [9b2d78b0bca85389f59b099e3c32ca29f21866b3](https://github.com/OlympusDAO/bophades/pull/131/commits/9b2d78b0bca85389f59b099e3c32ca29f21866b3) by implementing the recommended functions to calculate the appropriate `min` and `max` values.

However, [fuzzing the values](https://gist.github.com/zobront/aa4ed40a03f08f3de43ae4b6083af82f) showed there was some loss of precision in the calculations that could allow values slightly outside the bounds. Additional precisions and bound checks were added in [58d04cbd193c957924c14d20fd3889a99955b8c2](https://github.com/OlympusDAO/bophades/pull/131/commits/58d04cbd193c957924c14d20fd3889a99955b8c2), which led to the desired behavior.

## [H-02] If AMO becomes primary depositor of Silo, user can force withdrawals to get inflated interest rates

This issue is the inverse of [H-01], where the SiloAMO can be forced to deposit additional funds, decreasing rates for borrowers until 1 day later when `update()` can be called again.

In this case, we can imagine a situation where the SiloAMO becomes the primary depositor in the market. This is likely, as there is no reason to believe the market equilibrium for depositing OHM will align with the `uopt` and the interest rate at a near-optimal value calculated using `ki`. AMOs allow the rates determined by the protocol to become the market rates, whether or not the market agrees with these rates.

In the event that the majority of the deposited OHM is from the AMO, a user can manipulate the AMO to withdraw their funds, leading to a critically overutilized supply and dramatically increased interest rates.

A user who is a depositor of OHM in the pool could do this to benefit from the increased interest rates.

As a simple example of what this might look like:
- There is 100,000 OHM in the pool, close to all of which comes from the AMO
- Given the 50% optimal utilization rate, this means that 50,000 is borrowed
- A user deposits 100,000 OHM to the system
- The next block, they call `update()`, which causes the AMO to withdraw all its funds to maintain equilibrium
- The user then withdraws 50,000 OHM, leading to a utilization rate of 100% and massive interest rates

The `update()` function cannot be called again, and the market will need to wait for other users to jump in and fund deposits, or else regular borrowers of OHM will dramatically overpay for their borrows.

This sequence of events could be repeated daily, or even alternated with #155, making the market unusable for regular users.

### Recommendation

Following any of the recommended fixes for H-01 will solve this issue as well.

### Review

Fixed as recommended in [4bce45602daa4ee49b1ef52acf6f88021d1390d7](https://github.com/OlympusDAO/bophades/commit/4bce45602daa4ee49b1ef52acf6f88021d1390d7).

## [H-03] Yield cannot be harvested because wrong token is passed to Incentives Controller

In order to harvest rewards from Silo, the SiloAMO contains a `harvestYield()` function. This function checks the rewards balance of the contract, and then calls `claimRewards()` to claim them.

```solidity
function harvestYield() external {
    ISiloIncentivesController incentivesController_ = ISiloIncentivesController(
        incentivesController
    );

    address[] memory assets = new address[](1);
    assets[0] = address(OHM);

    // Get claimable rewards
    uint256 claimableRewards = incentivesController_.getRewardsBalance(assets, address(this));

    // Claim rewards
    if (claimableRewards > 0)
        incentivesController_.claimRewards(assets, claimableRewards, address(this));
}
```
Currently, the `harvestYield()` function is set to use the `OHM` token. However, Silo does not pay incentives based on the underlying token, but rather based on the collateral and debt tokens associated with it.

We can see this because, in [BaseIncentivesController.sol](https://github.com/silo-finance/silo-core-v1/blob/master/contracts/external/aave/incentives/base/BaseIncentivesController.sol), we get the total amount staked by the user and in total by calling `_getScaledUserBalanceAndSupply()`. This incentive mechanism is taken from Aave, who returns the staked values with this function.

However, looking at the function implementation on [SiloIncentivesController.sol](https://github.com/silo-finance/silo-core-v1/blob/master/contracts/incentives/SiloIncentivesController.sol), these values are calculated by simply taking the user's balance and the `totalSupply()`. This works because all collateral and debt tokens are all considered "staked" (because they represent use of the Silo), whereas underlying tokens are not.

We can verify this on the live deployment of this contract at [0x6c1603aB6CecF89DD60C24530DdE23F97DA3C229](https://etherscan.io/address/0x6c1603aB6CecF89DD60C24530DdE23F97DA3C229). Currently, there are only emissions being paid on the debt token, however, if we use a previous block (`17407114`), we can see that emissions were paid on both the collateral and debt tokens, but not on the underlying or collateral only tokens.

```solidity
contract SiloRewardsTest is Test {
    address ohm = 0x64aa3364F17a4D01c6f1751Fd97C2BD3D7e7f1D5;
    address collateralToken = 0x907136B74abA7D5978341eBA903544134A66B065;
    address collateralOnlyToken = 0xFDdfEd73b29B8859c6AE234aD64E2841614De559;
    address debtToken = 0x85A44Ff42F6B89125a541F64c77840977b0097E2;

    SiloIncentivesController incentives = SiloIncentivesController(0x6c1603aB6CecF89DD60C24530DdE23F97DA3C229);

    function testWhichTokensHaveIncentives() public {
        vm.createSelectFork("RPC_URL", 17407114);
        uint104 emissionsPerSecond;

        (emissionsPerSecond,,) = incentives.assets(ohm);
        console.log("OHM: ", emissionsPerSecond);

        (emissionsPerSecond,,) = incentives.assets(collateralToken);
        console.log("Collateral: ", emissionsPerSecond);

        (emissionsPerSecond,,) = incentives.assets(collateralOnlyToken);
        console.log("Collateral Only: ", emissionsPerSecond);

        (emissionsPerSecond,,) = incentives.assets(debtToken);
        console.log("Debt: ", emissionsPerSecond);
    }
}
```
```
Logs:
  OHM:  0
  Collateral:  6430041152263380
  Collateral Only:  0
  Debt:  38580246913580
```

### Recommendation

Adjust the `harvestYield()` function to use the `collateralToken` that will be owned by the Policy (0x907136B74abA7D5978341eBA903544134A66B065) rather than the `OHM` token.

### Review

Fixed as recommended in [8cc65de58ed541d95e5998a26c77ded2367b79d1](https://github.com/OlympusDAO/bophades/commit/8cc65de58ed541d95e5998a26c77ded2367b79d1).

## [H-04] AMO model opens up OHM treasury to increased risk

While H-01 and H-02 describe specific ways that users might manipulate the AMO for their own gain, there is a more general risk associated with connecting the OHM `MINTR` with an external contract in an automated way.

In essence, what the SiloAMO is doing is using the externally set `uopt` value as an input that directly feeds to `MINTR` to determine new OHM deployed to the market.

The `uopt` value is determined by the Silo Finance team and not by the market. Markets are expected to function because users are self interested and weighing information, and the balance of users on both sides leads to rates, liquidity, and risks that these individuals deem appropriate. Blunting the market's judgment with automation is a risky proposition.

As an example of how this could cause a problem, imagine there is an exploit on Silo Finance that allows OHM to be drained. Instead of simply stealing what is in the Silo, the AMO provides the hacker with a tap directly into the `MINTR` contract to steal additional OHM.

Similar risks exist in less extreme situations, where conditions might encourage the market to shift in a way that the AMO doesn't allow. For example, in the event of an XAI depeg, all XAI depositors would want to maximize borrows against their assets. This would usually max out the borrows of OHM in the Silo, but the direct tap into the `MINTR` would provide exit liquidity for more XAI holders.

### Recommendation

Similar to H-01 and H-02, there are a number of possible solutions, but my preferred solution is to impose bounds on the `update()` function to only operate when `uopt` is between `ulow` and `ucrit`.

In the event that the utilization rate falls outside of these bounds, a manual call to `deposit()` or `withdraw()` will need to be made by the Olympus team to restart the AMO.

This effectively ensures that, in any extreme market conditions, the AMO will turn off and not be exploitable.

### Review

Fixed as recommended in [4bce45602daa4ee49b1ef52acf6f88021d1390d7](https://github.com/OlympusDAO/bophades/commit/4bce45602daa4ee49b1ef52acf6f88021d1390d7).

## [M-01] ohmDeployed will become inaccurate if circulatingOhmBurned is used

The OHM deposited to Silo will accure interest over time, which means that the protocol has the potential to withdraw more OHM than is tracked by the `ohmDeployed` value.

This is expected, and the Policy performs valid adjustments to account for it:
```solidity
if (ohmDeployed < amount_) circulatingOhmBurned += amount_ - ohmDeployed;
ohmDeployed -= ohmDeployed > amount_ ? amount_ : ohmDeployed;
```
If more OHM is withdrawn than was deployed, `ohmDeployed` is set to 0, and the `circulatingOhmBurned` value is incremented as a sort of negative marker for the amount of surplus OHM that was withdrawn.

However, in the event that OHM continues to be deployed to the Silo, this `circulatingOhmBurned` value is not used to adjust the `ohmDeployed` value to accurately offset for the previous negative value.

Let's walk through an example:
- 1000 OHM is deployed to the Silo
- Additional interest is earned, so this value increases to 1010 OHM
- All 1010 OHM is withdrawn, setting `ohmDeployed = 0` and `circulatingOhmBurned = 10`
- A new 1000 OHM is deployed
- We have no deployed 2000 OHM and withdrawn 1010 OHM, which results in a total mint of `2000 - 1010 = 990 OHM`
- However, `ohmDeployed` will be set to 1000

This will cause two problems for the protocol:

1) `_canDeposit` will return false for any deposits that push the `ohmDeployed` over the `maximumToDeploy`, even if the total deployed is not actually greater than `maximumToDeploy`. This will cause all such deposits to revert.

2) Any time `update()` is called in a way that would push us over the `maximumToDeploy` will have the amount automatically reduced to `maximumToDeploy - ohmDeployed`, which will lead to too little OHM being deployed relative to the amount set in `maximumToDeploy`.

While these differences would be small on a short timescale, as the amount of interest earned increases, the difference can become more and more significant.

### Recommendation

The `_deposit()` function should be sure to clear out the `circulatingOhmBurned` before incrementing `ohmDeployed`:
```diff
function _deposit(uint256 amount_) internal {
    // Update state
+   uint cachedCirculatingOhmBurned = circulatingOhmBurned;
+   if (cachedCirculatingOhmBurned > amount_) {
+       circulatingOhmBurned -= amount_;
+   else if (cachedCirculatingOhmBurn > 0) {
+       circulatingOhmBurned = 0;
+       ohmDeployed += amount_ - cachedCirculatingOhmBurned;
+   } else {
        ohmDeployed += amount_;
+   }
```

### Review

Fixed as recommended in [8465e3dec2eb8b597851c543cc4b6d4c04006494](https://github.com/OlympusDAO/bophades/commit/8465e3dec2eb8b597851c543cc4b6d4c04006494).

## [M-02] SiloAMO uses outdated InterestRateModel

The new SiloAMO policy is intended to be deployed with the Silo interest rate model at address `0x7e9e7ea94e1ff36e216a703D6D66eCe356a5fd44` (as used in the fork tests and confirmed by the Olympus team).

If we check that contract address, we can see that the file deployed is `InterestRateModel.sol`.

If we check [that file in the Silo repo](https://github.com/silo-finance/silo-core-v1/blob/e5d16f201ab2139829d45ed881532c936249d3a5/contracts/InterestRateModel.sol), we can see that it's been edited to include the following line:

```
/// @notice DEPRECATED. Please use InterestRateModelV2 instead.
```

We can confirm this by calling the `getInterestRateModel()` function on the [SiloRepository contract](https://etherscan.io/address/0xd998C35B7900b344bbBe6555cc11576942Cf309d) with the Silo address and the OHM address.
```
interface SiloRepository {
    function getInterestRateModel(address silo, address ohm) external view returns (IInterestRateModel);
}

interface IInterestRateModel {}

contract InterestRateModelTest is Test {
    SiloRepository rep = SiloRepository(0xd998C35B7900b344bbBe6555cc11576942Cf309d);

    function testCorrectInterestRateModel() public {
        vm.createSelectFork("https://mainnet.infura.io/v3/fb419f740b7e401bad5bec77d0d285a5");
        address silo = 0xf5ffabab8f9a6F4F6dE1f0dd6e0820f68657d7Db;
        address ohm = 0x64aa3364F17a4D01c6f1751Fd97C2BD3D7e7f1D5;
        address model = address(rep.getInterestRateModel(silo, ohm));
        console.log(model);
    }
}
```
This results in the following output:
```
0x76074C0b66A480F7bc6AbDaA9643a7dc99e18314
```

### Recommendation

The correct `InterestRateModelV2` address should be used in both fork tests and deployment: 0x76074C0b66A480F7bc6AbDaA9643a7dc99e18314.

### Review

Fixed as recommended in [a605e8ef59d9d91db77ef4ce5097f88b59e2331d](https://github.com/OlympusDAO/bophades/commit/a605e8ef59d9d91db77ef4ce5097f88b59e2331d).

## [M-03] If MINTR is paused, SiloAMO will not be able to unwind its position

There are two situations when the SiloAMO will withdraw OHM from the Silo:

1) The OHM deposits in the Silo relative to borrows results in a utilization rate greater than `uopt`, and `update()` is called.

2) The admin or emergency roles of SiloAMO decide to reduce the position or (in the case of an emergency) unwind the entire AMO, so either `withdraw()` or `emergencyUnwind()` is called.

In either of these cases, `_withdraw()` is called, which withdraws OHM from the Silo and then burns it:
```solidity
function _withdraw(uint256 amount_) internal {
    // The OHM deposit will accrue interest over time leading to the potential to withdraw more OHM
    // than is tracked by the ohmDeployed value. This is fine, but we need to avoid underflow errors
    // and track the amount of OHM that has been burned from the circulating supply after being accrued
    // as interest
    if (ohmDeployed < amount_) circulatingOhmBurned += amount_ - ohmDeployed;
    ohmDeployed -= ohmDeployed > amount_ ? amount_ : ohmDeployed;

    // Withdraw OHM from Silo
    ISilo(market).withdraw(address(OHM), amount_, false);

    // Burn received OHM
    _burnOhm(amount_);

    emit Withdrawal(amount_);
}
```
```solidity
function _burnOhm(uint256 amount_) internal {
    OHM.increaseAllowance(address(MINTR), amount_);
    MINTR.burnOhm(address(this), amount_);
}
```
However, if MINTR is paused, the `MINTR.burnOhm()` function will revert because it has the `onlyWhileActive` modifier:
```solidity
modifier onlyWhileActive() {
    if (!active) revert MINTR_NotActive();
    _;
}
```
While it may seem unlikely that these two things happen at the same time, it is easy to envision that an emergency situation for OHM would require pausing the MINTR and unwinding all AMOs.

In this case, if the MINTR is paused first, it will be impossible to withdraw the OHM from the Silo, and the position will remain stuck at what could be a highly volatile time.

### Recommendation

When `MINTR.burnOhm()` is called in the `_burnOhm()` function, it should be wrapped in a `try/catch` block that will allow the function to continue (keeping the assets so they can be later swept to the admin) even if the MINTR is paused.

```diff
function _burnOhm(uint256 amount_) internal {
    OHM.increaseAllowance(address(MINTR), amount_);
-   MINTR.burnOhm(address(this), amount_);
+   try MINTR.burnOhm(address(this), amount_) {} catch {}
}
```
### Review

Fixed as recommended in [4e3925521d374627f0ad01c835b537961baa1ba8](https://github.com/OlympusDAO/bophades/commit/4e3925521d374627f0ad01c835b537961baa1ba8).

## [L-01] Yield can only be withdrawn to the admin address, not the treasury

When incentives are harvested using the `harvestYield()` function, the yield — which is paid in SILO tokens — is kept in the contract.

The only way to withdraw this ERC20 is to use the `sweepTokens()` function, which sends the balance to the admin.

```solidity
function sweepTokens(address token_) external onlyRole("lendingamo_admin") {
    ERC20(token_).transfer(msg.sender, ERC20(token_).balanceOf(address(this)));
}
```

However, as confirmed by the team, the yield tokens should be sent to the treasury rather than the individual admin.

### Recommendation

At the end of the `harvestYield()` function, send the `claimableRewards` directly to the treasury rather than keeping them in the contract.

### Review

Fixed as recommended in [bf8eb11efd04577789a26d3f9ff49329535682ce](https://github.com/OlympusDAO/bophades/commit/bf8eb11efd04577789a26d3f9ff49329535682ce).

## [L-02] Admin has unlimited power to mint new OHM

While the SiloAMO system appears to have many checks and balances, in the form of a permissionless `update()` function and a `maximumToDeploy` cap on OHM deployed, all these checks can be circumvented by a malicious admin.

While I don't see an incentive for the admin to do this, it is important to be aware of the risk.

1) The admin can adjust the `maximumToDeploy` cap, effectively minting unlimited OHM:
```solidity
function setMaximumToDeploy(uint256 newMaximum_) external onlyRole("lendingamo_admin") {
    maximumToDeploy = newMaximum_;
}
```
2) The admin could change to a malicious `rateModel`, which could cause user updates to force arbitrary amounts of OHM into the Silo:
```solidity
function setRateModel(address newRateModel_) external onlyRole("lendingamo_admin") {
    rateModel = newRateModel_;
}
```
3) The admin could call `deposit()` to mint the OHM to the Silo manually, and increase `updateInterval` to a large enough value that users will never be able to call the permissionless `update()` function:
```solidity
function setUpdateInterval(uint256 newInterval_) external onlyRole("lendingamo_admin") {
    updateInterval = newInterval_;
}
```

### Recommendation

Be aware of the centralization risks present in this part of the system, and ensure that the `lendingamo_admin` role is protected as a multisig to avoid the risk of compromised keys or a malicious actor.

### Review

Acknowledged. The only `lendingamo_admin` will be the primary multisig, which is trusted.

## [L-03] `update()` can be DOS'd by frontrunning with dust deposits and withdrawals

The `update()` function on the SiloAMO has the following check to protect against flash loans being used to manipulate the utilization rate:
```solidity
ISilo.UtilizationData memory utilizationData = ISilo(market).utilizationData(address(OHM));
if (utilizationData.interestRateTimestamp == block.timestamp)
    revert AMO_UpdateReentrancyGuard(address(this));
```
This `utilizationData.interestRateTimestamp` is updated every time `_accrueInterest()` is called on the Silo. This occurs each time funds are deposited, withdrawn, borrowed, or repaid.

This gives a user the ability to grief the `update()` function by frontrunning it and using one of these functions each block.

While this usually will not be economical, there could be situations (such as those described in [H-01] and [H-02]) where the incentive would be there to spend the gas to perform such an attack, especially on lower-cost chains like Arbitrum.

### Recommendation

If a solution to H-01 is decided that removes the need for flash loan protections, this check can be removed. Otherwise, it is a risk the system will likely need to acknowledge and deal with.

### Review

The fix to H-01 removed the need for flash loan protections, so this issue was resolved in [4bce45602daa4ee49b1ef52acf6f88021d1390d7](https://github.com/OlympusDAO/bophades/commit/4bce45602daa4ee49b1ef52acf6f88021d1390d7).

## [I-01] MINTR.decreaseMintApproval permission is set, but is never used

When the SiloAMO.sol policy is deployed, the `requestPermissions()` function includes the following 6 permissions:
```solidity
requests = new Permissions[](6);
requests[0] = Permissions(MINTR_KEYCODE, MINTR.mintOhm.selector);
requests[1] = Permissions(MINTR_KEYCODE, MINTR.burnOhm.selector);
requests[2] = Permissions(MINTR_KEYCODE, MINTR.increaseMintApproval.selector);
requests[3] = Permissions(MINTR_KEYCODE, MINTR.decreaseMintApproval.selector);
requests[4] = Permissions(LENDR_KEYCODE, LENDR.addAMO.selector);
requests[5] = Permissions(LENDR_KEYCODE, LENDR.removeAMO.selector);
```
However, the `MINTR.decreaseMintApproval()` function is never used within the policy, and therefore doesn't need to be given permission.

### Recommendation

```diff
-  requests = new Permissions[](6);
+  requests = new Permissions[](5);
   requests[0] = Permissions(MINTR_KEYCODE, MINTR.mintOhm.selector);
   requests[1] = Permissions(MINTR_KEYCODE, MINTR.burnOhm.selector);
   requests[2] = Permissions(MINTR_KEYCODE, MINTR.increaseMintApproval.selector);
-  requests[3] = Permissions(MINTR_KEYCODE, MINTR.decreaseMintApproval.selector);
-  requests[4] = Permissions(LENDR_KEYCODE, LENDR.addAMO.selector);
+  requests[3] = Permissions(LENDR_KEYCODE, LENDR.addAMO.selector);
-  requests[5] = Permissions(LENDR_KEYCODE, LENDR.removeAMO.selector);
+  requests[4] = Permissions(LENDR_KEYCODE, LENDR.removeAMO.selector);
```

### Review

Fixed as recommended in [49555e7e6c3cc9316df0a1dabb28b8d419258c90](https://github.com/OlympusDAO/bophades/commit/49555e7e6c3cc9316df0a1dabb28b8d419258c90).

## [I-02] Emergency Unwind can be performed in one transaction

Currently, for the SiloAMO to be unwound, two function calls are required.

First, `setEmergencyUnwind()` is called to set the `shouldEmergencyUnwind` flag to true. This function can only be called by the `emergency_admin` role.

Second, `emergencyUnwind()` is called, which validates that the flag is set to true before performing the unwind. This function is also restricted to be called by the `emergency_admin` role.

It would be more efficient for these two functions to be combined into one, since they have the same access controls and would only be called directly one after the other.

### Recommendation

Combine these two functions into a single `emergencyUnwind()` function, where the unwind occurs and the flag is set (in order to prevent future deposits and updates).

### Review

Fixed as recommended in [c0f696add9f3346f1d21e5fe06c241685a4579b0](https://github.com/OlympusDAO/bophades/commit/c0f696add9f3346f1d21e5fe06c241685a4579b0).

## [I-03] Comment in `getTargetDeploymentAmount()` specifies wrong decimals

In `getTargetDeploymentAmount()`, the `config.uopt` is returned from the `rateModel`.

```solidity
function getTargetDeploymentAmount() public view returns (uint256 targetDeploymentAmount) {
    ISiloInterestRateModel.Config memory config = ISiloInterestRateModel(rateModel).getConfig(
        market,
        address(OHM)
    );
    ISilo.UtilizationData memory utilizationData = ISilo(market).utilizationData(address(OHM));

    // This is the optimal utilization percentage formatted with 19 decimals
    // This is int256 but should never be negative, so we can safely cast to uint256
    int256 optimalUtilizationPct = config.uopt;
    uint256 totalBorrowed = utilizationData.totalBorrowAmount;

    // Optimal utilization percentage is formatted with 18 decimals, so we need to multiply by 1e18
    targetDeploymentAmount = totalBorrowed.mulDiv(1e18, uint256(optimalUtilizationPct));
}
```
The comment specifies that the optimal utilization percentage is formatted with 19 decimals, but it actually uses 18 decimals. This can be seen in [Silo's documentation](https://silopedia.silo.finance/interest-rates/market-interest-model-configuration#reading-the-interest-model-configuration-for-an-asset) where they specify that `500000000000000000` (0.5e18) represents 50%.

The code handles this correctly, but the comment should be fixed.

### Recommendation

```diff
-   // This is the optimal utilization percentage formatted with 19 decimals
+   // This is the optimal utilization percentage formatted with 18 decimals
    // This is int256 but should never be negative, so we can safely cast to uint256
    int256 optimalUtilizationPct = config.uopt;
    uint256 totalBorrowed = utilizationData.totalBorrowAmount;
```

### Review

Fixed as recommended in [b1283b54acc68e228569ebfbe7d9f0d79210ceb1](https://github.com/OlympusDAO/bophades/commit/b1283b54acc68e228569ebfbe7d9f0d79210ceb1).
