<table>
    <tr>
        <td><img src="https://images.crunchbase.com/image/upload/c_lpad,h_256,w_256,f_auto,q_auto:eco,dpr_1/chdz3qoiiuxobsdjpw9s" width="250" height="250" /></td>
        <td>
            <h1>Fungify Audit Report</h1>
            <h2>Fungify Lending Pools Protocol</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: Nov 29 to Dec 15, 2023</p>
        </td>
    </tr>
</table>

# About **Fungify**

Fungify is a non-custodial NFT index and algorithmic lending protocol, allowing for instant NFT sales, immediate NFT-backed loans, and a yield-bearing NFT index token.

Fungify Lending Pools is their first product, a fully general solution to the rest of NFT DeFi, allowing NFT shorting, cross-margined NFT collateralized loans, and lending yields on NFTs.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Lead Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

The [fungify-dao/taki-contracts](https://github.com/fungify-dao/taki-contracts/) repository was audited at commit [b13d6f10c09d5594e0ee41ac63ed8516f05bab52](https://github.com/fungify-dao/taki-contracts/commit/b13d6f10c09d5594e0ee41ac63ed8516f05bab52).

The following new contracts were in scope:
- contracts/CErc20InterestMarket.sol
- contracts/CErc20InterestMarketDelegate.sol
- contracts/CErc20InterestMarketDelegator.sol
- contracts/CErc20InterestMarketInterfaces.sol
- contracts/CErc20InterestMarketNoProxy.sol
- contracts/CErc721.sol
- contracts/ERC721Interfaces.sol
- contracts/CErc721Delegate.sol
- contracts/CErc721Delegator.sol
- contracts/CErc721InterestRateModel.sol
- contracts/CErc721NoProxy.sol
- contracts/CErc721TokenInterfaces.sol
- contracts/CEtherDelegate.sol
- contracts/CEtherDelegator.sol
- contracts/ChainlinkPriceOracle.sol
- contracts/FloorPriceFeedAdapter.sol
- contracts/LiqPriceFeedAdapter.sol
- contracts/token/FungToken.sol
- contracts/token/StraightSale.sol
- contracts/token/proxy/FungTokenProxy.sol
- contracts/token/proxy/Proxy.sol
- contracts/token/proxy/StraightSaleProxy.sol
- contracts/token/proxy/Upgradeable.sol

The following contracts were to be considered as a diff from Compound:
- contracts/BaseJumpRateModelV2.sol
- contracts/CErc20.sol
- contracts/CErc20Delegate.sol
- contracts/CErc20Delegator.sol
- contracts/CErc20Immutable.sol
- contracts/CEther.sol
- contracts/CToken.sol
- contracts/CTokenInterfaces.sol
- contracts/Comptroller.sol
- contracts/ComptrollerInterface.sol
- contracts/ComptrollerStorage.sol
- contracts/EIP20Interface.sol
- contracts/EIP20NonStandardInterface.sol
- contracts/ErrorReporter.sol
- contracts/ExponentialNoError.sol
- contracts/InterestRateModel.sol
- contracts/JumpRateModel.sol
- contracts/JumpRateModelV2.sol
- contracts/PriceOracle.sol
- contracts/SafeMath.sol
- contracts/SimplePriceOracle.sol
- contracts/Timelock.sol
- contracts/Unitroller.sol
- contracts/WhitePaperInterestRateModel.sol

After completion of the fixes, [PR #8](https://github.com/fungify-dao/taki-contracts/pull/8) and [PR #9](https://github.com/fungify-dao/taki-contracts/pull/9/) were reviewed. Additional changes made after the audit and not included in these PRs were not reviewed.

# Summary of Findings

| Identifier | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [C-01] | Liquidators seizing NFTs retain their interest index, allowing theft of funds from interest market | Critical | ✓ |
| [H-01] | Interest isn't charged on accrued interest in ERC721 market, allowing attacker to earn free yield | High | ✓ |
| [H-02] | ERC721 interest model miscalculates utilization rate due to reserves | High | ✓ |
| [H-03] | High ERC721 utilization rate can be exploited to steal funds | High | ✓ |
| [H-04] | Interest collected before being paid leads to problematic accounting for Interest Markets | High | ✓ |
| [M-01] | Collateral token interest is accrued after relative price calculation in liquidations | Medium | ✓ |
| [M-02] | NFT oracle missing Chainlink liveness checks | Medium | ✓ |
| [M-03] | BaseJumpRateModelV2 uses outdated blockPerYear value | Medium | ✓ |
| [M-04] | Liquidated NFTs can earn more than liquidation incentive | Medium | ✓ |
| [M-05] | No check that NFTs aren't being claimed for free in `topUpInterestShortfall()` | Medium | ✓ |
| [M-06] | Some NFTs may be incompatible with pools due to `totalSupply()` check | Medium | ✓ |
| [M-07] | All payable calls will revert when sent to CEtherDelegator | Medium | ✓ |
| [M-08] | `beforeRatio` taken before interest accrual in liquidations | Medium | ✓ |
| [M-09] | `topUpInterestShortfall` does not accrue interest on tokens | Medium | ✓ |
| [M-10] | Uncollected interest on NFTs not counted in liquidity calculation | Medium | ✓ |
| [L-01] | Interest market's `initialize()` function is skipped due to incorrect signature | Low | ✓ |
| [L-02] | Stale price delays will start at 0, allowing currently stale prices to be used | Low | ✓ |
| [L-03] | `getAccountDebtRatio()` behaves unexpectedly | Low | ✓ |
| [L-04] | Underlying oracle decimals should be confirmed by `FloorPriceFeedAdaptor` | Low | ✓ |
| [L-05] | `doNFTTransferIn()` should not perform fee on transfer token check | Low | ✓ |
| [L-06] | Domain separator of FUNG token will temporarily be set to 0 before initialization | Low | ✓ |
| [L-07] | Unchecked math in price oracle is not guaranteed to be safe | Low | ✓ |
| [I-01] | Chainlink Price Floor NFT feeds require special attention | Informational | ✓ |
| [I-02] | FUNG deployment combines upgradeable and non-upgradeable patterns | Informational | |
| [I-03] | ERC721 callback isn't used | Informational | ✓ |

# Detailed Findings


## [C-01] Liquidators seizing NFTs retain their interest index, allowing theft of funds from interest market

When an NFT is used as collateral for a liquidated loan and is seized as collateral, the `_seize()` function performs the following logic:
- call `accrueInterest()`, which updates the borrowIndex, supplyIndex, totalReserves, and accrualBlockNumber
- round up the number of tokens seized to the nearest whole NFT
- ensure the borrower is on the liquidator
- move `accountTokens` from borrower to liquidator

While the `accrueInterest()` logic updates the global variables, the borrower or liquidator do not have their `interestAccrued` or `interesstIndex` values updated at this point. This has the consequence that the liquidator will end up with the additional seized tokens, but with their original `interestIndex`, allowing them to claim interest for these new tokens on the index increases since their `interestIndex`.

This exploit can be used maliciously to extract additional interest from the pool, potentially even putting the solvency of the interest market at risk. To understand why, consider the following scenario:
- Alice the Attacker deposits a BAYC NFT and immediately withdraws is, which sets her supply `interestIndex` to the current value.
- Years later, Bob deposits a BAYC NFT. He withdraws interest and acts like a typical user. Eventually, due to borrowed token appreciation (or BAYC depreciation) he ends up in a shortfall.
- Alice can liquidate Bob's loan to claim his BAYC. At that point, she will have a BAYC deposited and an `interestIndex` that is multiple years old.
- This will allow her to claim interest as if she had loaned that BAYC for years. That interest can be collected and immediately redeemed for USDC, which comes out of the interest market.

In an extreme case, a user could farm hundreds of addresses with old `interestIndex` values by minting and redeeming the same NFT through each of them. Later, they could create hundreds of liquidatable positions (using other wallets) and liquidate themselves to claim an unbounded amount of unearned interest.

In this case, it is likely that the amount of phony interest earned would outstrip the actual interest paid by such a substantial amount that the interest market could be drained of all its funds.

### Proof of Concept

The following test can be run to demonstrate this exploit. It follows the same logic outlined above: an attacker mints and immediately redeems to "prime" an account for the later attack by locking in the supply interest index. Later, they create a liquidatable position and immediately liquidate it, but are able to claim the full interest for the time period since their initial "priming" of the account.

You can find the `BaseTest.t.sol` file, which is used as the backbone for all POCs in this report, [in this Gist](https://gist.github.com/zobront/44a1909a8451d7649443d0e2717a96ab).

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BaseTest.t.sol";

contract SeizeInterestTest is BaseTest {
    function testSeizeInterest() public {
        // attacker mints and redeems to lock in interest index
        _distributeAndMintBAYC(attacker, 99);
        vm.prank(attacker);
        baycCERC721.redeemUnderlying(1);

        // some other users enter the market (don't matter for POC but market must have some activity)
        _distributeAndMintBAYC(lender, 1);
        _distributeERC20(USDC, borrower, 100_000e6, address(imMarket));
        vm.startPrank(borrower);
        imMarket.mint(100_000e6);
        baycCERC721.borrow(1);
        vm.stopPrank();

        // 1 year passes
        vm.roll(block.number + blocksPerYear);
        baycCERC721.accrueInterest();

        // another user deposits some BAYC and borrows max to set up for liquidation
        // note that the attacker could do this themselves
        address user = makeAddr("user");
        _distributeAndMintBAYC(user, 2);
        _distributeAndMintBAYC(user, 3);
        vm.prank(user);
        imMarket.borrow(100_000e6);

        // at this point, nobody should be owed anything
        console2.log("Attacker Interest Owed: ", baycCERC721.supplyInterestCurrent(attacker));
        console2.log("User Interest Owed: ", baycCERC721.supplyInterestCurrent(user));

        // to allow for simple liquidation, let's increase price of USDC by 2%
        MockOracle usdcMoonOracle = new MockOracle(1.02e8);
        oracle.setAssetPriceFeed(CToken(address(imMarket)), address(usdcMoonOracle));

        // liquidate the user
        uint[] memory empty = new uint[](0);
        Comptroller.Liquidatables memory liqable = Comptroller.Liquidatables(address(imMarket), 50_000e6, empty);
        Comptroller.Liquidatables[] memory liqables = new Comptroller.Liquidatables[](1);
        liqables[0] = liqable;
        CTokenInterface[] memory collaterals = new CTokenInterface[](1);
        collaterals[0] = CTokenInterface(address(baycCERC721));
        _distributeERC20(USDC, attacker, 50_000e6, address(imMarket));
        vm.startPrank(attacker);
        comptroller.batchLiquidateBorrow(user, liqables, collaterals);
        console2.log("Attacker Interest Owed After Liq: ", baycCERC721.supplyInterestCurrent(attacker));

        // redeem the fake interest and cash it out for USDC
        uint balanceBeforeCashOut = IERC20(USDC).balanceOf(attacker);
        baycCERC721.redeemInterest(address(0));
        imMarket.redeem(imMarket.balanceOf(attacker));
        vm.stopPrank();
        console2.log("Attacker Final USDC Claimed: ", IERC20(USDC).balanceOf(attacker) - balanceBeforeCashOut);
    }

        function _distributeAndMintBAYC(address user, uint tokenId) internal {
        _distributeERC721(BAYC, user, tokenId, address(baycCERC721));
        uint[] memory baycIds = new uint[](1);
        baycIds[0] = tokenId;
        vm.prank(user);
        baycCERC721.mint(baycIds);
    }
}
```
```
Logs:
  Attacker Interest Owed:  0
  User Interest Owed:  0
  Attacker Interest Owed After Liq:  6650667536
  Attacker Final USDC Claimed:  6650667536
```

In this case, we use 1 account over 1 year and the attack earns $6650. However, this attack can be performed an unbounded amount of times, so repeating this strategy 1000+ times (or with a longer wait period) would result in millions of dollars of funds being stolen from the interest market.

### Recommendation

Use the same logic used in `transferTokens` to checkpoint the `interestIndex` and `interestAccrued` values of the borrower and liquidator before transferring the tokens from one to the other.

### Review

Fixed as recommended in [84f24cad84e82128d94e8ba485abaf14a5fefdbb](https://github.com/fungify-dao/taki-contracts/pull/9/commits/84f24cad84e82128d94e8ba485abaf14a5fefdbb).

## [H-01] Interest isn't charged on accrued interest in ERC721 market, allowing attacker to earn free yield

When a user borrows an ERC721, the interest they are charged is stored in the `borrowSnapshot.interestAccrued` field of the ERC721 market. Only when the interest is paid does it become a balance in the interest market.

This causes a discrepancy because the accrued interest is effectively being borrowed from the interest market at 0%. At the same time, the lender on the other side of this trade who has earned this interest is free to withdraw it from the interest market at any time. This effectively amounts to the interest market paying the borrower's interest for them.

This can be exploited by a user to either get a free loan or to earn free yield on their assets by acting as both a lender and a borrower on the ERC721 market, claiming all the interest earned, but keeping the interest owed tucked away in the market.

### Proof of Concept

To understand this more deeply, let's look at an example of an attacker who lends themselves a large number of NFTs on an ERC721 market. Note that this can easily be done because the borrowed NFTs can be re-added to the protocol. Therefore, a user can easily repeat the "lend & borrow" cycle until they have an arbitrary amount of funds lent through the market.

They will also need to add some separate collateral (which will earn interest) in order to make sure the account stays solvent.

As interest is accrued on the NFT position, the user will be able to collect the earned interest and deposit it into the USDC market, where it will earn further interest. However, they can leave the interest owed on the NFT position in the market, where it will not accrue interest.

Over time, this allows the attacker to claim a compounding stream of USDC (in the interest market), in exchange for holding a non-compounding balance of interest owed (in the NFT market).

### Note on Impact

Because of the Virtual Balance feature, the interest market will allow the user to continue claiming interest, even when the pool doesn't have the USDC backing to support it. A further consequence of this is that the attacker may choose to redeem the USDC from the interest market and deposit it into another market. At the limit, this would lead to lack of solvency for the interest market, as attackers could withdraw all the USDC available, while the rest is effectively "hidden" in the NFT market as `interestAccrued`.

### Recommendation

This is a challenging problem, as it is deeply intertwined with the core architecture of the protocol. Let's discuss it further.

Some ideas:
- Is there a way to checkpoint the interest accrued directly to the interest market?
- Is there an additional liquidation mechanism that could be added that, if a user has too much interest accrued, their NFT position could be liquidated?

### Review

Fixed in [PR #8](https://github.com/fungify-dao/taki-contracts/pull/8) by using CTokens to store accrued interest instead of underlying. This exposes unclaimed interest to changes in interest market exchange rate, which removes the delta in earnings between claimed and unclaimed interest.

## [H-02] ERC721 interest model miscalculates utilization rate due to reserves

Like the other interest models, `CErc721InterestModel.sol` calculates the utilization rate as follows:
```solidity
function utilizationRate(uint cash, uint borrows, uint reserves) public pure returns (uint) {
    // Utilization rate is 0 when there are no borrows
    if (borrows == 0) {
        return 0;
    }

    return borrows * BASE / (cash + borrows - reserves);
}
```
This formula makes sense in other markets, because `reserves` are fees earned by the protocol that will show up in the `cash` value (they are tokens held by the market), but should not be taken into account, because they are owned by the protocol and cannot be borrowed.

However, in the ERC721 market, this is not the case. Reserves is incremented as interest is accrued, but it represents the number of CTokens that can be claimed in the interest market. Therefore, it has no bearing on the utilization rate.

As reserves pile up (and especially if there is ever an interest market using an 18 decimal token, like DAI), this value will play a larger and larger role in the utilization rate calculation, which can cause two major problems:

1) As `reserves` gets larger, the utilization rate will approach infinity, causing interest rates to grow.

2) If `reserves` exceeds `cash + borrows`, it will cause the utilization rate function to revert, bricking the market.

### Recommendation

The utilization rate should be calculated wihout taking the reserves value into account.

### Review

Fixed as recommended in [524828510aa6519749bd2f77a1bdde2fe8cce64e](https://github.com/fungify-dao/taki-contracts/pull/9/commits/524828510aa6519749bd2f77a1bdde2fe8cce64e).

Note that this fix corrects the miscalculation in the ERC721 market. It remains that the ERC20 Interest Market rate will be slightly off due to the reserves value not taking into account any reserves that are piling up in the ERC721 market but have not yet been claimed. The Fungify team has acknowledged this risk.

## [H-03] High ERC721 utilization rate can be exploited to steal funds

As discussed in [H-02], the utilization rate for ERC721 markets can become extremely high if the `reserves` value becomes large.

If the interest market is ever set up with an 18 decimal token, an attacker can exploit this vulnerability to force liquidate innocent users or to steal funds from the interest market.

There are two important facts that contribute to this issue:

1) As the value of `reserves` approaches the value of `cash + borrows`, the utilization rate approaches infinity. Utilization rates are intended to be capped at 1e18 ([see Compound code comment](https://github.com/compound-finance/compound-protocol/blob/a3214f67b73310d547e00fc578e8355911c9d376/contracts/BaseJumpRateModelV2.sol#L78)), whereas our value can go much higher.

2) The supply rate is calculated in most Compound forks only for convenience. In the ERC721 market, however, it is used to manually calculate the increase in supply interest index, so it is critical that it is calculated correctly. This value is calculated as `utilizationRate(cash, borrows, reserves) * (borrowRate * oneMinusReserveFactor / BASE) / BASE);`

This supply rate is calculated by multiplying the reduced borrow rate by the utilization rate, because the propotion of funds on the borrow side vs the supply side is equal to `utilization rate`. If we take the increase in borrow interest and want to apply it to the users' supply interest, we need to scale it down by utilization rate to ensure that (ignoring protocol fees) `borrow $ * borrow rate == supply $ * supply rate`.

In the situation where `utilizationRate` is increased above `1e18`, the result is that the supply rate is made much higher than the borrow rate. The only check performed on the rates returned is that `borrowRateMantissa > borrowRateMaxMantissa`, but the supply rate can far exceed this value as the utilization rate grows. This should never be the case. Because there isn't actually more money being borrowed than supplied, the result is that more interest can be collected from the pool than will be paid into it. This could lead to lack of solvency for the interest market.

### Proof of Concept

An attacker can exploit these facts as follows:
- Let's imagine an ERC721 market.
- An attacker can cycle an ERC721 through the market by lending it, then borrowing it, etc until they have a large amount of funds borrowed.
- As interest is accrued, it will lead to reserves being added to the market (USDC that can be claimed by the protocol from the interest market). After paying their fees, the attacker can unwind their deposits and borrows.

While there is a hard limit of `borrowRateMaxMantissa` on how high the borrow rate can go, there is no limit on the supply rate, which is calculated as follows:
```solidity
uint rateToPool = borrowRate * oneMinusReserveFactor / BASE;
uint supplyRate = utilizationRate(cash, borrows, reserves) * rateToPool / BASE;
```
In other words, we scale the supply rate by utilization rate. This means the supply rate can grow substantially higher than the borrow rate. This allows the attack to lend funds on the pool to earn this massive supply rate, and claim more interest than was paid to the interest market, leading to a loss of solvency.

### Note on Impact

Note that, while these situations are extreme, a smaller version of this will be happening organically in the protocol whenever reserves are included in the utilization rate.

### Recommendation

Remove `reserves` from the utilization rate calculation.

Additionally, for safety, add an explicit check either that (a) the utilization rate is always less than 1e18 or (b) the supply rate is always less than the borrow rate.

### Review

Fixed as recommended (both new calculation and safety check) in [524828510aa6519749bd2f77a1bdde2fe8cce64e](https://github.com/fungify-dao/taki-contracts/pull/9/commits/524828510aa6519749bd2f77a1bdde2fe8cce64e).

## [H-04] Interest collected before being paid leads to problematic accounting for Interest Markets

Because additional interest is not accrued on the `interestAccrued` value of ERC721 markets, the incentive is for users to avoid repaying for as long as possible. The more the interest market CToken appreciates, the less CTokens they will owe for the same amount of interest, so it is in the user's best interest to hold their CTokens, continuing to earn on them in the form of appreciation, before repaying.

Similarly, users who earn interest on the ERC721 market are incentivized to collect it as early as possible. Once it's collected on, they will get real interest market CTokens that will earn interest, which is more valuable than a static amount owed on the ERC721 market.

The result is that users are likely to collect, on average, significantly sooner than they will pay. This will lead to a Virtual Balance in the interest market.

However, any time there is a Virtual Balance, the accounting of the interest market will be thrown off, towards insolvency. This is because we adjust the total supply down to ensure that the exchange rate represents the number of non-virtual tokens. However, when interest is earned on the interest market, the increased exchange rate can be claimed by all users, including those whose tokens came from virtual balances.

It is easy to see that this creates insufficient backing for the token in the short run. However, because the ERC721 interest is paid later at this artificial exchange rate, the result is a "locking in" of this unbacked situation, which will lead to long term, permanently insolvency.

### Proof of Concept

To see this, let's look at a simple example that exaggerates the values for simplicity:
- There are three users in the interest market, Alice, Bob, and Charlie. Alice and Bob are also in the ERC721 market.
- In the interest market, Alice has 20 CTokens and Bob has 80 CTokens. The exchange rate is 1:1, so the total supply is 100 CTokens. Charlie has borrowed half of this USDC, so cash is 50 USDC and borrows is 50 USDC.
- In the ERC721 market, Alice has lent Bob an NFT.

Let's go through the example outlined above, where Alice collects her interest long before Bob pays his.
- Alice collects 60 USDC of interest. This brings her balance up to 80 CTokens. Total supply is now 160, but offset by 60 virtual balance. The exchange rate remains at 1:1.
- Over time, the interest market earns interest because of Charlie's borrow. For simplicity, let's use 100% interest. Now Charlie's borrows are 100 USDC and total borrows is 100 USDC. This brings the exchange rate up to 1.5:1.
- Later, Bob repays his ERC721 interest. Because of the exchange rate, he only needs to pay 40 CTokens for the 60 USDC owed. He loses 40 CTokens, which reduce the total supply and virtual balance. He now has 40 CTokens, and the total supply is 120 CTokens (offset by a virtual balance of 20). Exchange rate is unchanged.

The result of this state is that we have 150 USDC of cash + borrows, and 120 CTokens. The NFT market has netted out (interest paid == interest collected), but the 120 CTokens in the interest market should be able to cash out 180 USDC. The market is no longer solvent, and now requires interest to be repaid ahead of collections in order to regain solvency, which will never happen.

### Note on Impact

Note that the correct rational response to this situation would be to redeem all interest market CTokens as soonas possible, which will create a run on the bank dynamic.

Also note that this reduces the trustworthiness of the interest market as a form of collateral for other assets. One can imagine a situation where the actual USDC backing the CTokens is less than 85% of what is reflected, and we end up in a situation where a large enough holder would not be liquidated despite being insolvent because liquidators would not be able to cash into USDC to make the transaction net positive.

### Recommendation

The accounting of the interest market requires that the virtual balance be included in the exchange rate. However, it seems that this could open up other unintended risks, such as exchange rate manipulation via interest payment.

It may be required to simply not allow interest to be collected until the interest market is solvent (ie no virtual balance), and have some forcing function to ensure users of the ERC721 market must pay in a timely manner.

### Review

This is fixed in [PR #8](https://github.com/fungify-dao/taki-contracts/pull/8/files#diff-fb9a60eaf9cec845c450ebd19be806d10e5eccd5ca9c21fb7cbaccca8538b406) along with H-01. Combining this fix with the "top up interest" liquidation mechanism, ensures that all accrued interest on the NFT market is fully backed by interest market tokens that adjust according to exchange rate changes on the interest market.

## [M-01] Collateral token interest is accrued after relative price calculation in liquidations

When `batchLiquidateBorrow()` is called, we calculate the amount of collateral tokens to seize by taking the amount of liquidatable assets paid back and finding the relative exchange rate between the two. This logic is performed in `liquidateCalculateSeizeTokensNormed()`:
```solidity
function liquidateCalculateSeizeTokensNormed(address cTokenCollateral, uint normedRepayAmount) public view returns (uint) {
    uint priceCollateralMantissa = oracle.getUnderlyingPrice(CToken(cTokenCollateral));
    if (priceCollateralMantissa == 0) {
        revert PriceError();
    }

    uint exchangeRateMantissa = CToken(cTokenCollateral).exchangeRateStored(); // Note: reverts on error
    uint numerator = liquidationIncentiveMantissa * normedRepayAmount * expScale;
    uint denominator = priceCollateralMantissa * exchangeRateMantissa;

    uint seizeTokens = numerator / denominator;

    return seizeTokens;
}
```
This function sets the denominator to `priceCollateralMantissa * exchangeRateMantissa`, which is equivalent to the USD value of the underlying asset multiplied by the exchange rate from underlying asset to CToken. In other words, it represents the USD value of the CToken. This is used for the conversion.

However, the CToken has not had interest accrued at this point. That happens later, when `_seize()` is called.
```solidity
uint seizeTokens = liquidateCalculateSeizeTokensNormed(address(cTokenCollaterals[i]), liquidatedValueRemaining);
uint actualSeizeTokens;

uint borrowerBalance = cTokenCollaterals[i].balanceOf(borrower);
if (borrowerBalance < seizeTokens) {
    // can't seize more collateral than owned by the borrower
    actualSeizeTokens = borrowerBalance;
} else {
    actualSeizeTokens = seizeTokens;
}

actualSeizeTokens = cTokenCollaterals[i]._seize(msg.sender, borrower, actualSeizeTokens);
```
The result is that, if interest has not been accrued in a while, the exchange rate will be artificially low, and the liquidator will be able to seize more collateral than they should be able to.

This is limited by ensuring that the borrower's debt ratio has approved throughout the liquidation, so there is a limit to how much funds can be taken. However, for a market that has had a substantial time pass without accruing interest, the liquidator could get up to `1 / (1 - collateralFactor)` as a reward, instead of the 8% that is intended.

### Recommendation

`liquidateCalculateSeizeTokensNormed()` should include a call to `cTokenCollateral.accrueInterest()` before calculations are performed to ensure they are accurate.

### Review

Fixed via the fix to M-08 (which accrues interest before the debt ratio is calculated) in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [M-02] NFT oracle missing Chainlink liveness checks

When `getUnderlyingPrice()` is called on the Chainlink oracle, the recommended liveness checks are performed:
```solidity
(
    /*uint80 roundID*/,
    int rate,
    /*uint startedAt*/,
    uint updatedAt,
    /*uint80 answeredInRound*/
) = feed.latestRoundData();

...

// check if price is stale
uint stalePriceDelay = stalePriceDelays[asset];
if (stalePriceDelay != 0 && block.timestamp > updatedAt + stalePriceDelay) {
    revert StalePrice();
}
```
However, in the `FloorPriceFeedAdaptor`, we calculate the NFT's USD value by pulling from two separate oracles and combining the values. When these values are pulled, no liveness checks are performed:
```solidity
function latestAnswer() public view returns (int256) {
    (
        ,
        int floorRate,
        ,
        ,

    ) = floorPriceFeed.latestRoundData();

    (
        ,
        int ethRate,
        ,
        ,

    ) = ethPriceFeed.latestRoundData();

    return floorRate * ethRate / 1e18; // scale to 8 decimals places like Chainlink
}
```

When the adaptor returns the `latestRoundData()` to the oracle, it fills in all values except the price with 0s.

```solidity
function latestRoundData()
    public
    view
    returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    ) {
    return (0, latestAnswer(), 0, 0, 0);
}
```

However, a return value of `0` will not pass the stale price check. Instead, `0` will lead any updated time that isn't at the exact current timestamp to fail the check.

As a result, any NFT oracle that has a `stalePriceDelay` added will be unusable and revert whenever it is called.

The result is that we will need to skip stale price checks, allowing outdated prices that can lead to inaccurate liquidations. This is especially important because Chainlink's NFT Floor Price Feeds are considered "Specialized Feeds" (less secure, see [I-01]), so need to be carefully monitored.

### Recommendation

It is recommended to add the same liveness checks to the `FloorPriceFeedAdaptor` as are used in the Chainlink oracle.

### Review

Fixed as recommended in [d603c6636266cee9d62434c839f58821de5ee193](https://github.com/fungify-dao/taki-contracts/pull/9/commits/d603c6636266cee9d62434c839f58821de5ee193).

## [M-03] BaseJumpRateModelV2 uses outdated blockPerYear value

In `BaseJumpRateModelV2.sol`, which is intended to be used as the rate model for all non-ERC721 markets, we use the following constant for `blocksPerYear`:
```solidity
uint public constant blocksPerYear = 2102400;
```
This value is used when setting interest rates, which are inputted on an annual basis and adjusted to the per block rate using the following function:
```solidity
function updateJumpRateModelInternal(uint baseRatePerYear, uint multiplierPerYear, uint jumpMultiplierPerYear, uint kink_) internal {
    baseRatePerBlock = baseRatePerYear / blocksPerYear;
    multiplierPerBlock = (multiplierPerYear * BASE) / (blocksPerYear * kink_);
    jumpMultiplierPerBlock = jumpMultiplierPerYear / blocksPerYear;
    kink = kink_;

    emit NewInterestParams(baseRatePerBlock, multiplierPerBlock, jumpMultiplierPerBlock, kink);
}
```
This value is forked from Compound, but is outdated. It was set before the merge, and estimated an average block time of `1 / (2102400/365/24/60/60) = 15 seconds`.

Since the merge, blocks are only 12 seconds. Using the formulas above, we can see that this results in a 25% increase in the calculated interest rate over what was intended.

```
baseRatePerYear = 1e18
baseRatePerBlock = 1e18 / 2102400 = 476190476190476
actualRatePerYear = 476190476190476 * 2628000 = 1.25e18
```

### Recommendation

Update the `blocksPerYear` constant to `(60/12)*60*24*365 = 2628000`, which reflects the current block spacing of 12 seconds per block.

### Review

Fixed by setting the `blockPerYear` value in the constructor in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [M-04] Liquidated NFTs can earn more than liquidation incentive

The liquidation incentive (currently set to 1.08x) is used to calculate the surplus collateral a liquidator will receive in excess of the amount they repay. It is intended to define the liquidation rewards.

This works by allowing the liquidator to input the tokens they wish to repay, and the collateral tokens they'd like to be paid in. After repayment is complete, the liquidation function iterates over each collateral token, calculates 1.08x the amount that is left to be repaid, and transfers up to that amount (less if the borrower's balance is less) to the liquidator.

However, in the case that an ERC721 is the collateral token being seized, the number of tokens is rounded up to the nearest `oneNFTAmount` and sends the full additional NFT's value to the liquidator. In the NFT's value is greater than the remaining repayment amount, this can lead to rewards that are far greater than the intended 1.08x liquidation incentive.

Fortunately, at the end of liquidation, we perform the following check, which ensures that we improved the user's debt ratio through the liquidation:
```solidity
(err, afterRatio) = getAccountDebtRatio(borrower);
if ((err != uint(Error.NO_ERROR) && err != uint(Error.TOO_LITTLE_INTEREST_RESERVE)) || afterRatio > beforeRatio) {
    revert LiquidateSeizeTooMuch();
}
```
However, since for every $1 we repay, we are removing $1 of debt from the user but only `$1 * collateralFactor` collateral, any liquidation that takes less than `1 / collateralFactor` of a liquidation incentive will still pass this check.

As the tests are currently set up, all markets have a collateral factor of 0.85. This would allow a liquidator to select a repayment amount that would lead to a `1 / 0.85 = 1.176x` liquidation incentive, more than the 1.08x that was intended.

In the situation where collateral factors are lowered, this could lead to even more extreme liquidation rewards.

### Recommendation

Liquidations where ERC721s are used as collateral should enforce that the repayment amount is sufficient so that the seized NFTs only provide the intended liquidation incentive.

### Review

Fixed by tracking liquidation excess value in [8b40302136258c3bc2a9724706d00395eff222cd](https://github.com/fungify-dao/taki-contracts/pull/9/commits/8b40302136258c3bc2a9724706d00395eff222cd) and then enforcing a refund mechanism in [aa04b99c96bdc11242ef92180fdd204f977767e9](https://github.com/fungify-dao/taki-contracts/pull/9/commits/aa04b99c96bdc11242ef92180fdd204f977767e9).

## [M-05] No check that NFTs aren't being claimed for free in `topUpInterestShortfall()`

In the `topUpInterestShortfall()` function, we allow a liquidator to top up the interest balance of a borrower, in exchange for an equal amount of any of their collateral tokens.

Because NFTs are only liquidated or traded in round increments, the following logic ensures the amount used to top up and the amount of collateral tokens received are of equal value:
```solidity
if (CTokenInterface(cTokenCollateral).marketType() == 2) {
    // nft market
    uint oneNFTAmount = doubleScale / exchangeRateCollateralMantissa;
    if (actualSeizeTokens % oneNFTAmount != 0) {
        // ensure whole nft seize size by rounding up to the next whole NFT
        actualSeizeTokens = ((actualSeizeTokens / oneNFTAmount) + 1) * oneNFTAmount;
    }
}

uint borrowerBalance = CTokenInterface(cTokenCollateral).balanceOf(borrower);
if (borrowerBalance < actualSeizeTokens) {
    actualSeizeTokens = borrowerBalance;
}

if (actualSeizeTokens != seizeTokens) {
    actualTopUpTokens = actualTopUpTokens * actualSeizeTokens / seizeTokens;
}
```
In other words, we round the NFT up to the nearest increment. Then, if that changes the amount, we take the percentage increase over what should have been seized (`actualSeizeTokens / seizeTokens`) and multiply it by the top up amount to adjust the top up amount equally.

However, there is no explicit check that the starting top up amount is not zero. In this case, the proportional increase will not do anything, and the NFT will be seized for free.

The starting top up amount is calculated as follows:
```solidity
uint actualTopUpTokens = shortfallUsd * doubleScale / (priceInterestMantissa * exchangeRateInterestMantissa);
```

While it is conceptually possible for this amount to equal zero, it seems that with the parameters used in the deployment script, the `shortfallUsd` value, when converted into an 18 decimal number, will always end up sufficiently high to ensure this isn't possible.


### Recommendation

While this doesn't appear to currently be exploitable, given that there could be an edge case to accomplish this that I missed, or that parameters would change in the future, it is recommended to perform an explicit check that we don't have a seized amount greater than zero while providing zero top up tokens.

```solidity
if (actualTopUpTokens == 0 && actualSeizeTokens > 0) {
    revert TopUpZero();
}
```

Note that this is similar to the checks that are performed in the `redeem()` functions to ensure rounding does not lead to free redemptions.

### Review

Fixed as recommended in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [M-06] Some NFTs may be incompatible with pools due to `totalSupply()` check

When initializing a new ERC721 market, we end the `initialize()` function with a `totalSupply()` call to the underlying NFT.
```solidity
function initialize(address underlying_,
    ComptrollerInterface comptroller_,
    InterestRateModel interestRateModel_,
    uint initialExchangeRateMantissa_,
    string memory name_,
    string memory symbol_,
    uint8 decimals_
) public {

    ...

    // Set underlying and sanity check it
    underlying = underlying_;
    EIP20Interface(underlying).totalSupply();
}
```
This is forked from a check that Compound performs on their `CErc20` markets, which is intended to ensure that the underlying token is a valid ERC20. This check makes sense because `totalSupply()` is required by the [EIP20 standard](https://eips.ethereum.org/EIPS/eip-20).

However, the [EIP721 NFT standard](https://eips.ethereum.org/EIPS/eip-721) does not require a `totalSupply()` function. It is a part of the enumerable extension, which is commonly used, but there are many NFTs that don't include this function. As a result, these valid NFTs will not be compatible with the `CErc721` market.

### Recommendation

Remove the sanity check in the `CErc721` market, and simply ensure that you are inputting the correct underlying asset when new markets are set up.

### Review

Fixed as recommended in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [M-07] All payable calls will revert when sent to CEtherDelegator

The Delegator contracts are intended to pass along any calls to their corresponding implementations.

Some delegators perform this logic by manually implementing each underlying function. Others (such as `CEtherDelegator.sol`) simply use a fallback function which is intended to capture all possible calls to the implementation.

However, the fallback function of this contract contains a check that was taken from the other markets but does not apply to CEther:
```solidity
fallback() external payable {
    if (msg.value > 0) {
        revert CannotReceiveValueGtZero();
    }

    ...
}
```
This will revert in the case that any payable function call are sent to the contract.

Looking at `CEther.sol`, minting, repaying, adding reserves, or WETH withdrawals all require the ability to receive ETH.

Fortunately, there is a payable `delegateToImplementation()` function on the delegator, so all calls from users will be possible by sending their calls to that function, with encoded abi data instead. While this is inconvenient, it is not a security risk.

WETH withdrawals, on the other hand, can only be accepted by a payable `fallback()` or `receive()` function. These will revert when sent to the delegator, and so all liquidations will revert when WETH is attempted to be withdrawn.

### Note on Specifics

Currently, the CEtherDelegator inherits from CEther. This means it is not a delegator. It contains all functionality itself, as well as having an identical implementation that it can delegate call out to.

This inherited contract contains all of the CEther functionality, including the ability to accept payments, so this bug is not currently a problem. However, when the other issue is fixed (which would presumably happen by inherting an interface from CEther instead of the full functionality), this bug will become a problem.

### Recommendation

The easiest fix would be to remove the option to do a proxy contract for CEther, and instead implement it as an immutable non-proxy contract, the same way Compound does.

If this is not preferable, then ensure that (a) the inheritance is such that the delegator is working as a proxy and (b) the fallback function allows for ETH to be received.

### Review

Fixed by removing the proxy option for CEther in [cd578511b94985956325d8ea1d95d3c5a9925af4](https://github.com/fungify-dao/taki-contracts/pull/9/commits/cd578511b94985956325d8ea1d95d3c5a9925af4).

## [M-08] `beforeRatio` taken before interest accrual in liquidations

In `batchLiquidateBorrow()`, the fundamental check on the liquidation is that the account debt ratio after is less than or equal to what it was before.

```solidity
if ((err != uint(Error.NO_ERROR) && err != uint(Error.TOO_LITTLE_INTEREST_RESERVE)) || afterRatio > beforeRatio) {
    revert LiquidateSeizeTooMuch();
}
```
Along the pathway to liquidation, all relevant markets have their interest accrued (either in the `_liquidateBorrow()` function or the `_seize()` function), which increases the value of both the debt and collateral tokens.

These accruals happen after the `beforeRatio` is taken, but before the `afterRatio` is taken. Therefore, the values of the tokens will be shifted between these two checks.

This can lead to a situation where the liquidation takes too much collateral that it actually harms the debt position of the borrower, but is allowed to proceed.

For example, imagine a situation where a borrower has 5 cTokens of collateral worth $1 each (not accrued) and 1 cTokens of debt worth $4.50 (fully accrued). This leads to a `beforeRatio` of `4.5 / (5 * 0.85) = 1.058e18`. If there are interest accruals due that will move the value of the collateral tokens up 25%, and the borrower seizes 1 cToken (unpaid), the resulting `afterRatio = 4.5 / ((5 - 1) * 1.25 * 0.85) = 1.058e18`.

Clearly taking a collateral token without paying any debt off is not good for the borrower, but it will be allowed to pass by this check before the interest accrual mismatch.

Note that in some edge cases, this could also cause the problem of allowing a non-liquidatable position to be liquidated, but this is less likely because it presumes that the position was previously in a liquidatable state but wasn't liquidated.

### Note on Exploitability

Because of the logic used to calculate the amount of tokens seized, there is no way for a liquidator to directly choose to seize tokens without paying any debt off. However, this can be combined with issues like [M-01] and [M-04] to lead to additional rewards beyond the `1 / (1 - collateralFactor)` that the liquidator can earn.

### Recommendation

Explicitly call `accrueInterest()` on all liquidatable and collateral tokens when `batchLiquidateBorrow()` is called.

If this is done, it negates the need for the fix suggested for [M-01].

### Review

Fixed as recommended in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [M-09] `topUpInterestShortfall()` does not accrue interest on tokens

Similar to the above issue, the `topUpInterestShortfall()` function does not explicitly accrue interest for either the interest market token or the collateral token.

This leads to a number of possible problems:
- The call to `getAccountLiquidity()` can revert if the user is in shortfall before accrual but would be in good standing after.
- The call to `getAccountLiquidity()` can pass if accruing interest on a borrowed token would have pushed the user into a shortfall.
- The call to `getAccountLiquidity()` can return an inaccurate interest shortfall if the interest market has not been recently accrued.
- The `_adjustTopUpValues()` calculation will use out of date exchange rates for both tokens, skewing results.

### Recommendation

Explicitly call `accrueInterest()` on both tokens when `topUpInterestShortfall()` is called.

### Review

Fixed as recommended in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [M-10] Uncollected interest on NFTs not counted in liquidity calculation

When `getHypotheticalAccountLiquidityInternal()` is called to calculate whether a user's overall account is in good standing or has a shortfall, it calculates the value of their collateral (discounted by the collateral factor) and borrows to compare.

In order to ensure we are accounting for the interest owed on NFT borrows, we get the interest balance from `getAccountSnapshot()`:
```solidity
(oErr, vars.cTokenBalance, vars.borrowBalance, vars.exchangeRateMantissa, vars.interestBalance) = asset.getAccountSnapshot(account);
```
We then use this balance to calculate the value of the interest owed:
```solidity
vars.sumInterestOwed = vars.sumInterestOwed + vars.interestBalance * interestOraclePriceMantissa / 1e18;
```
This `sumInterestOwed` balance is used to check whether the account is in an interest market shortfall, which can trigger the `Error.TOO_LITTLE_INTEREST_RESERVE` and allow other users to top up the interest market and seize collateral.

`sumInterestOwed` is also added to the total borrows that are used to check whether the full account is in shortfall:
```solidity
vars.sumBorrowPlusEffects = vars.sumBorrowPlusEffects + vars.sumInterestOwed;
```
However, we do not perform equivalent logic for the interest earned on NFT collateral. This will cause the balance of interest market tokens owned and overall collateral of the account to both be understated, which could lead to unjustified liquidations.

### Recommendation

Add additional logic to the `getHypotheticalAccountLiquidityInternal()` function to account for the interest earned on NFT collateral.

### Review

All NFT markets will have their interest accrued before any liquidation or top up. This change is made in [c243e3c09103e62a2dcbd9f3300c5f0bf1202983](https://github.com/fungify-dao/taki-contracts/pull/9/commits/c243e3c09103e62a2dcbd9f3300c5f0bf1202983) and [83c9ec7de3a139fe4eba3ccd0ed88515fc7a71f7](https://github.com/fungify-dao/taki-contracts/commit/83c9ec7de3a139fe4eba3ccd0ed88515fc7a71f7).

## [L-01] Interest market's `initialize()` function is skipped due to incorrect signature

Both `CErc20InterestMarketDelegator.sol` and `CErc20InterestMarketNoProxy.sol` call the underlying implementation's `initialize()` function in their constructor.

Looking at the no proxy version as an example, we see:
```solidity
initialize(
    underlying_,
    comptroller_,
    interestRateModel_,
    initialExchangeRateMantissa_,
    name_,
    symbol_,
    decimals_,
    3
);
```
We can see that this funciton call has 8 arguments, ending in a `3`, which represents the interest market type.

Looking at the interest market's `initialize()` function, we see the following:
```solidity
function initialize(address underlying_,
    ComptrollerInterface comptroller_,
    InterestRateModel interestRateModel_,
    uint initialExchangeRateMantissa_,
    string memory name_,
    string memory symbol_,
    uint8 decimals_
) public {
    super.initialize(underlying_, comptroller_, interestRateModel_, initialExchangeRateMantissa_, name_, symbol_, decimals_, 3);
}
```
We can see that this function signature does not include a `marketType` argument. Instead, `3` is hardcoded into the call to the parent's `initialize()` function.

When the `initialize()` function is called from the constructor, we skip the `CErc20InterestMarket.sol#initialize()` function and instead skip right over it into the parent's function.

Because the function doesn't do anything except call to its parent, this currently causes no harm. However, if any logic were added to this `initialize()` function, it would be skipped.

### Recommendation

Change the `initialize()` calls in the constructors of `CErc20InterestMarketDelegator.sol` and `CErc20InterestMarketNoProxy.sol` to skip the final `marketType` argument, which will be added by the `CErc20InterestMarket.sol#initialize()` function.

### Review

Fixed for Delegator in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

Fixed for NoProxy in [cd578511b94985956325d8ea1d95d3c5a9925af4](https://github.com/fungify-dao/taki-contracts/pull/9/commits/cd578511b94985956325d8ea1d95d3c5a9925af4).

## [L-02] Stale price delays will start at 0, allowing currently stale prices to be used

When a new asset is added to the `ChainlinkPriceOracle`, it will default to having a stale price delay of 0. The `setStalePriceDelay()` function will need to be called separately to set the delay to the desired value.

The result is that, when a new oracle is added, there will be a short period between transactions where no stale price delay is set.

In this window, if the oracle is in fact stale, the stale price will be allowed to be used, which could allow undercollateralized borrows.

### Recommendation

Include the `stalePriceDelay` in the `setAssetPriceFeed()` function, so all values can be set atomically at once.

### Review

Fixed as recommended in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [L-03] `getAccountDebtRatio()` behaves unexpectedly

The Comptroller's `getAccountDebtRatio()` is a public view function that can be called by external contracts to determine the debt ratio of a given account.

The function is defined as follows:

```solidity
function getAccountDebtRatio(address account) public view returns (uint, uint) {
    // uint[4] memory retVals; /* liquidity, shortfall, sumCollateral, sumBorrowPlusEffects */
    (Error err, uint[4] memory retVals) = getHypotheticalAccountLiquidityInternal(account, CToken(address(0)), 0, 0);
    if (retVals[1] == 0) {
        return (uint(err), 0);
    } else if (retVals[2] == 0) {
        return (uint(err), type(uint).max);
    }
    return (uint(err), retVals[3] * 1e18 / retVals[2]);
}
```
In the case where the account is in a shortfall, the function returns `borrows * 1e18 / collateral`, which tells us the ratio of how underwater the account is.

However, in the case where the account is solvent, the function overrides and returns `0`.

For external callers, a returned value of `0` implies that the account has no debt, which will not be accurate.

### Recommendation

It is recommended to adapt the function to return the debt ratio correctly (which will require changes to the internal uses of the function in the liquidation flow). Rather than checking if the value is zero, the internal uses should be checking if the value is less than or equal to 1e18.

If this change is not desired, it is recommended to clearly specify in the function comments and documenation that it does not return a true debt ratio, and instead returns `0` for all solvent accounts.

### Review

Comments added to explicitly explain the behavior in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

Renamed function to better capture behavior in [f2a13efd8a7c73f67ed8162c4ac075ee6a4d271b](https://github.com/fungify-dao/taki-contracts/pull/9/commits/f2a13efd8a7c73f67ed8162c4ac075ee6a4d271b).

## [L-04] Underlying oracle decimals should be confirmed by `FloorPriceFeedAdaptor`

To calculate the value of the NFT in USD with 8 decimals of precision, the `FloorPriceFeedAdaptor` performs the following:
```solidity
return floorRate * ethRate / 1e18;
```
This takes the price of the NFT in ETH, multiplies it by the ETH price in USD, and divides by 1e18.

This should return 8 decimals because the `floorRate` will be in 18 decimals, the `ethRate` will be in 8 decimals, and the division will remove 18 decimals.

However, there is no validation that this is being used with oracles that conform to these expectations.

### Recommendation

It is recommended to add an explicit check to the `FloorPriceFeedAdaptor` constructor to ensure that the underlying oracles return values with the expected decimals of precision.

```diff
constructor(AggregatorV3Interface floorPriceFeed_, AggregatorV3Interface ethPriceFeed_) public {
+   require(floorPriceFeed_.decimals() == 18, "FloorPriceFeedAdaptor: floorPriceFeed decimals must be 18");
+   require(ethPriceFeed_.decimals() == 8, "FloorPriceFeedAdaptor: ethPriceFeed decimals must be 8");
    floorPriceFeed = floorPriceFeed_;
    ethPriceFeed = ethPriceFeed_;
}
```

### Review

Fixed as recommended in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [L-05] `doNFTTransferIn()` should not perform fee on transfer token check

In `doNFTTransferIn()`, we perform a check that is taken from the ERC20 market, checking the balance before and after the transfer, and adjusting the amount to the difference between these values.
```solidity
function doNFTTransferIn(address from, uint[] memory nftIds) virtual internal returns (uint) {
    // Read from storage once
    IERC721 underlying_ = IERC721(underlying);
    uint balanceBefore = underlying_.balanceOf(address(this));

    for(uint i = 0; i < nftIds.length;) {
        underlying_.transferFrom(from, address(this), nftIds[i]);
        heldNFTs.push(nftIds[i]);
        unchecked { i++; }
    }

    // Calculate the amount that was *actually* transferred
    uint balanceAfter = underlying_.balanceOf(address(this));
    return balanceAfter - balanceBefore;   // underflow already checked above, just subtract
}
```
While this situation should not be possible (the number of NFTs transferred should always equal the increase in balance), in the event that it does occur, we do not want to accept it as fact and move on. This would cause problems such as `heldNFTs` not having a length that is equal to the amount of tokens minted, as well as `repayAmount` being incorrect when calculating the interest payment.

### Recommendation

It would be preferable to revert in the situation where the balance delta does not equal `nftIds.length`.

### Review

Fixed as recommended in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [L-06] Domain separator of FUNG token will temporarily be set to 0 before initialization

In the FUNG token's `initialize()` function, we set the `DOMAIN_SEPARATOR` as follows:
```solidity
DOMAIN_SEPARATOR = keccak256(
    abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("Fung Token")),
        keccak256(bytes("1")),
        block.chainid,
        address(this)
    )
);
```
This value is then used in permit signatures to ensure they were intended to be applied in this context.

However, there is no check that the DOMAIN_SEPARATOR has been set before it is used. This means that, in the moments before the `initialize()` function is called, another signature could be used to claim a permit that would create an allowance for another's users tokens.

While it is incredibly unlikely that a user has such a signature from another user, it is recommended to ensure that only the correct signature can be used to approve token spending.

### Recommendation

```diff
function permit(
    address owner,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v,
    bytes32 r,
bytes32 s
) external {
    if (deadline < block.timestamp) {
        revert ExpiredPermit();
    }
+   if (DOMAIN_SEPARATOR == bytes32(0)) {
+       revert UninitializedDomainSeparator();
+   }
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))));
    address recoveredAddress = ecrecover(digest, v, r, s);
    if (recoveredAddress == address(0) || recoveredAddress != owner) {
        revert InvalidPermitSignature();
    }
    _approve(owner, spender, value);
}
```

### Review

Fixed as recommended in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [L-07] Unchecked math in price oracle is not guaranteed to be safe

In the Chainlink Price Oracle, we expect the price of the asset to be returned in 8 decimals. We then perform the following calculation to transfer it into `36 - asset decimals` decimals:
```solidity
unchecked { price = uint(rate) * 10**(28 - decimals[asset]); }
```
While this multiplication is likely to be safe in most practical cases, it is not guaranteed to be safe.

- `rate` is returned as an `int256`, which could be as high as `type(int256).max = 57896044618658097711785492504343953926634992332820282019728792003956564819967`
- this value is equal to the max `uint256` / 2, which will overflow when any decimal adjustment is applied to it

Practically, we can calculate the maximum safe value for `rate` as:
- `type(uint256).max / 10**28 = 11579208923731619542357098500868790785326998466564`
- any value greater than this can overflow when multiplying by decimals
- since `rate` is always returned in 8 decimals, this represents a value of approximately `11579208923731619542357098500868790785326998466564 / 10**8 = 115792089237316195423570985008687907853269 ~= 10**41`

In this situation, the price will overflow and result in the token being undervalued by the oracle.

### Recommendation

While it is unlikely that a token will return a value this high, it would be safer to remove the unchecked block to be sure.

### Review

Fixed as recommended in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).

## [I-01] Chainlink Price Floor NFT feeds require special attention

Chainlink provides a categorization of the security of all their feeds. As we can see on the [NFT Floor Price Feed](https://docs.chain.link/data-feeds/nft-floor-price/addresses?network=ethereum&page=1) page, each of the NFT Floor feeds is considered a "Specialized Feed".

Their documentation explains:

> [Specialized feeds] are purpose-built feeds that might rely heavily on contracts maintained by external entities. Typical users of these feeds are large institutional users with deep expertise in the market space they operate in.
> These feeds are monitored and well-supported, but they might not meet the same levels of resiliency as the above categories. We strongly advise you to speak with the Chainlink Labs team to understand their use cases, properties, and associated risks.

While they appear to be safe, Chainlink does not appear to publicly share the exact methodology and associated risks for this type of feed.

### Recommendation

Contact Chainlink's team via their [Contact Page](https://chain.link/contact?ref_id=DataFeed) to get an explanation of risks they foresee in NFT Price Floor Feeds and consider whether any of these risks may be a problem for the protocol.

### Review

Confirmed: "Our team communicates with Chainlink regularly and have discussed the NFT feeds at length."

## [I-02] FUNG deployment combines upgradeable and non-upgradeable patterns

The `FungToken.sol` and `StraightSale.sol` contracts are both upgradeable, but do not follow recommended conventions for upgradeable contracts.

It does not appear that this causes any security risk, but there are a number of small issues that result from it. For example:

1) FungToken uses the non-upgradeable OpenZeppelin ERC20 contract, which sets the `name` and `symbol` storage slots in the constructor. As a result, these values will be set on the implementation contract, rather than the proxy. This is solved by manually overriding the `name()` and `symbol()` functions to return the correct values, but results in both (a) the implementation contract returning the values and (b) the storage slots in the proxy remaining empty.

2) Upgradeable contracts usually keep extra storage "gaps" for future upgrades. For example, if OpenZeppelin upgrades their ERC20 implementation (say, due to a security vulnerability) or any of its inheriting contracts, and you decide you want to do the upgrade too, you will not be able to, because the storage slots will no longer line up.

3) It is not generally recommended to use standard storage slots (like 0 and 1) for the implementation and owner addresses. While you successfully ensure that they are not overridden by the proxy, it is recommended to use non-standard slots (such as the hashes of obscure values) to ensure they are not accidentally overridden by an SSTORE on the implementation contract.

### Recommendation

It is recommended to use OpenZeppelin's upgradeable contract library for upgradeable contracts, along with proxies with non-standard storage slots.

### Review

Acknowledged: "Our proxy is minimalist and less gas intensive than the OZ upgradable contracts. We take steps to ensure there's no storage collisions during upgrades. As you note, there are no security risks in our implementation, so we will keep things as is."

## [I-03] ERC721 callback isn't used

In `CErc721.sol`, we include the `onERC721Received()` function, which allows NFTs to be received only if they are sent by the contract itself.
```solidity
function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external override returns (bytes4) {
    if (operator != address(this)) {
        revert Unauthorized();
    }
    return IERC721Receiver.onERC721Received.selector;
}
```
However, there is only one place where NFTs are transferred into the contract, and that is in the `doNFTTransferIn()` function:
```solidity
function doNFTTransferIn(address from, uint[] memory nftIds) virtual internal returns (uint) {
    // Read from storage once
    IERC721 underlying_ = IERC721(underlying);
    uint balanceBefore = underlying_.balanceOf(address(this));

    for(uint i = 0; i < nftIds.length;) {
        underlying_.transferFrom(from, address(this), nftIds[i]);
        heldNFTs.push(nftIds[i]);
        unchecked { i++; }
    }

    ...
}
```
This function uses the `transferFrom` function, which does not check the ERC721 callback. The callback is only checked when `safeTransferFrom()` is used.

### Recommendation

Either remove the callback function entirely (so all calls using `safeTransferFrom()` will fail), or change the `doNFTTransferIn()` function to use `safeTransferFrom()`.

### Review

Fixed by implementation `safeTransferFrom` in [7e0ee60622ddcbf384657da480ef9c851f2adc11](https://github.com/fungify-dao/taki-contracts/pull/9/commits/7e0ee60622ddcbf384657da480ef9c851f2adc11).
