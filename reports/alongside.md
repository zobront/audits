<table>
    <tr><th></th><th></th></tr>
    <tr>
        <td><img src="https://media.licdn.com/dms/image/C4E0BAQFcbt5CILENEA/company-logo_200_200/0/1678793909021?e=2147483647&v=beta&t=6kjLYe4wJx6GygUPpwtvd0Kp4OSy4CqyBl3bLus_KQk" width="250" height="250" /></td>
        <td>
            <h1>Alongside Audit Report</h1>
            <h2>Index V2 & OP Migration</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: June 12 to 16, 2023</p>
        </td>
    </tr>
</table>

# About **Alongside**

Alongside is the first tokenized on-chain, broad-based crypto market index. It's index system creates the AMKT token, which provides holders with exposure to a market-cap weighted basket of 25 assets.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

The [Alongside-Finance/index-system-v2](https://github.com/Alongside-Finance/index-system-v2) repo was audited at [commit feb13c74d51472b2d3fdd8f5f653fa4452c78773](https://github.com/Alongside-Finance/index-system-v2/commit/feb13c74d51472b2d3fdd8f5f653fa4452c78773).

The following contracts were in scope:
- src/BridgedIndexToken.sol
- src/IndexToken.sol
- src/Common.sol
- src/ProposableOwnable.sol
- src/Vault.sol
- src/invoke/Bounty.sol
- src/invoke/HashStore.sol
- src/invoke/Issuance.sol
- src/lib/FixedPoint.sol
- src/lib/Multiplier.sol
- src/lib/VArray.sol
- src/scripts/CoreDeploy.s.sol
- src/scripts/MainnetInitialMigration.s.sol
- src/scripts/OPInitialMigration.s.sol

# Summary of Findings

| ID     | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [C-01] | currentMultiplier is calculated incorrectly, causing up to 86400x discounted issuance | Critical | ✓ |
| [H-01] | Token accounting can be permanently broken by malicious rebalancer | High | ✓ |
| [H-02] | If `feeScaled` is set too high in the constructor, the protocol will be bricked | High | ✓ |
| [H-03] | Fees are sent to vault instead of feeRecipient | High | ✓ |
| [M-01] | First mint could be frontrun to break L1 `totalSupply` calculation | Medium | ✓ |
| [M-02] | Owner can steal all funds locked in bridge by changing `REMOTE_TOKEN` value | Medium |  |
| [M-03] | `proposedOwner` not reset on transfer, allowing ownership to be seized back | Medium |  |
| [M-04] | If bounty is created without all underlying tokens, accounting will be permanently thrown off | Medium | ✓ |
| [M-05] | Authority address can (maliciously or accidentally) steal user funds from the vault | Medium |  |
| [M-06] | Allowing multiple bounties to be live at once creates race condition | Medium | ✓ |
| [M-07] | Vault should have two step ownership transfer | Medium |  |
| [M-08] | Inflation will be overapplied if there is a time period when `totalSupply() == 0` | Medium | ✓ |
| [M-09] | System implicitly relies on off chain oracle | Medium |  |
| [L-01] | Issuer can underpay for AMKT because values are rounded down | Low | ✓ |
| [L-02] | Users can dodge rebalancing costs by sandwiching rebalancer | Low |  |
| [L-03] | System cannot support atypical ERC20s | Low |  |
| [G-01] | Unnecessary ownership transfers in deploy script | Gas |  |
| [G-02] | Bounty can use `lastKnownMultiplier` instead of `multiplier()` to save gas | Gas |  |
| [G-03] | VArray can remove `included` field to save gas | Gas |  |
| [G-04] | `isRestricted` checks can be skipped if `msg.sender` is the minter address | Gas |  |
| [G-05] | `takeOwnership()` function checks can be simplified | Gas |  |
| [I-01] | `deployVault()` function `_indexTokenOwner` argument is misnamed | Informational |  |
| [I-02] | Try catch can be removed from `fulfillBounty()` | Informational |  |

Note that, in the process of performing fixes for this audit, the Alongside team decided to pause development of the contracts to think more about the issue raised in M-09. As a result, many of the less serious fixes were not made, and will be performed when development restarts in the future.

# Detailed Findings

## [C-01] currentMultiplier is calculated incorrectly, causing up to 86400x discounted issuance

Multiplier.sol returns a `currentMultiplier` value, which is intended to represent the multiplier up to the current second (as opposed to the tracked value, which is rounded to the latest day). The value is calculated as follows:

```solidity
uint256 dT = block.timestamp - trackedTimestamp;

if (dT != 0) {
    uint256 feePerSecondScaled = oneSubFee / 1 days;

    currentMultiplier = fmul(
        trackedMultiplier,
        feePerSecondScaled * dT
    );
} else {
    currentMultiplier = trackedMultiplier;
}
```
To translate: If there is a delta between the end of the latest day and the current time, calculate the `feePerSecondScaled` by dividing `oneSubFee` by the number of seconds in a day. Then multiply this value by the number of seconds that have passed, and multiply all that by the `trackedMultiplier` for the end of the latest day.

However, this logic is flawed. The `currentMultiplier` is intended to represent a discount that has been caused by fee inflation, and multiplying it by a very small value (which is what happens when the small fee per second value is multiplied by the number of seconds) results in a dramatic decrease in the multiplier.

This has a major impact, because this value is used by `realUnits()` to calculate the current holdings of each asset minus fees.

This value is used in the `issue()` function to determine the amount of underlying assets that need to be deposited in order to receive 1 `AMKT`. Because the values are understated, the function requires a significantly diminished amount of underlying assets.

The result is that a user can deposit ~86400x less underlying assets than they should, and mint `AMKT` at a discount.

## Proof of Concept

First, let's look at the current multiplier calculation in isolation. You can do this by dropping the following contract into your test suite, and running the tests with `forge test --match-function testZ__CurrentMultiplierAt1Day`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/lib/Multiplier.sol";

contract ZachTest is Test {
    function testZ__CurrentMultiplierAt1Day() public {
        uint lastTs = block.timestamp;
        vm.warp(block.timestamp + 1 days);
        uint lastMul = 1e18;
        uint feeScaled = 27260808837036;
        (,,, uint currMul) = Multiplier.computeMultiplier(lastTs, lastMul, feeScaled);
        console.log(currMul);
    }

    function testZ__CurrentMultiplierAt1DayPlus1() public {
        uint lastTs = block.timestamp;
        vm.warp(block.timestamp + 1 days + 1);
        uint lastMul = 1e18;
        uint feeScaled = 27260808837036;
        (,,, uint currMul) = Multiplier.computeMultiplier(lastTs, lastMul, feeScaled);
        console.log(currMul);
    }
}
```

```
Running 2 tests for test/Zach.t.sol:ZachTest
[PASS] testZ__CurrentMultiplierAt1Day() (gas: 7212)
Logs:
  999972739191162964

[PASS] testZ__CurrentMultiplierAt1DayPlus1() (gas: 7627)
Logs:
  11573443045433
```

As we can see, the `currentMultiplier` has decreased from 0.99e18 to 0.11e14, an 86400x decrease.

Now, let's step back and look at how this can be used to steal funds from the protocol. The following test can be dropped into `Issuance.t.sol` and run with `forge test --match-function testZ__IssuanceDiscounted`:

```solidity
function testZ__IssuanceDiscounted() public {
    seedInitial(10);

    vm.warp(block.timestamp + 1 days);

    TokenInfo[] memory realUnits = vault.realUnits();
    uint256[] memory startingBalances = new uint256[](realUnits.length);
    for (uint256 i; i < realUnits.length; i++) {
        startingBalances[i] = IERC20(realUnits[i].token).balanceOf(address(this));
    }

    uint snapshotId = vm.snapshot();

    // do the test at the 1 day mark
    mint(5e18);

    uint256[] memory correctSpend = new uint256[](realUnits.length);
    for (uint256 i; i < realUnits.length; i++) {
        correctSpend[i] = startingBalances[i] - IERC20(realUnits[i].token).balanceOf(address(this));
    }

    vm.revertTo(snapshotId);
    vm.warp(block.timestamp + 1);

    // redo the test at the 1 day + 1 second mark
    mint(5e18);

    for (uint256 i; i < realUnits.length; i++) {
        uint amountSpent = startingBalances[i] - IERC20(realUnits[i].token).balanceOf(address(this));
        console.log(realUnits[i].token);
        console.log("Correct Amount Spent: ", correctSpend[i]);
        console.log("Actual Amount Spent: ", amountSpent);
        console.log("Discount Rate: 1 / ", correctSpend[i] / amountSpent);
    }
}
```
This test copies the logic used by the existing test for issuance, but compares the amount of tokens spent to mint 5e18 AMKT at the 1 day mark to the 1 day plus 1 second mark.

The result is that each token is discounted by 86402x from the correct price:
```solidity
[PASS] testZ__IssuanceDiscounted() (gas: 10009092)
Logs:
  0xa0Cb889707d426A7A386870A03bc70d1b0697598
  Correct Amount Spent:  4999863695955814820
  Actual Amount Spent:  57867215227165
  Discount Rate: 1 /  86402
  0x1d1499e622D69689cdf9004d05Ec547d650Ff211
  Correct Amount Spent:  9999727391911629640
  Actual Amount Spent:  115734430454330
  Discount Rate: 1 /  86402
  0xA4AD4f68d0b91CFD19687c881e50f3A00242828c
  Correct Amount Spent:  14999591087867444460
  Actual Amount Spent:  173601645681495
  Discount Rate: 1 /  86402
  0x03A6a84cD762D9707A21605b548aaaB891562aAb
  Correct Amount Spent:  19999454783823259280
  Actual Amount Spent:  231468860908660
  Discount Rate: 1 /  86402
  0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF
  Correct Amount Spent:  24999318479779074100
  Actual Amount Spent:  289336076135825
  Discount Rate: 1 /  86402
  0x15cF58144EF33af1e14b5208015d11F9143E27b9
  Correct Amount Spent:  29999182175734888920
  Actual Amount Spent:  347203291362990
  Discount Rate: 1 /  86402
  0x212224D2F2d262cd093eE13240ca4873fcCBbA3C
  Correct Amount Spent:  34999045871690703740
  Actual Amount Spent:  405070506590155
  Discount Rate: 1 /  86402
  0x2a07706473244BC757E10F2a9E86fB532828afe3
  Correct Amount Spent:  39998909567646518560
  Actual Amount Spent:  462937721817320
  Discount Rate: 1 /  86402
  0x3D7Ebc40AF7092E3F1C81F2e996cbA5Cae2090d7
  Correct Amount Spent:  44998773263602333380
  Actual Amount Spent:  520804937044485
  Discount Rate: 1 /  86402
  0xD16d567549A2a2a2005aEACf7fB193851603dd70
  Correct Amount Spent:  49998636959558148200
  Actual Amount Spent:  578672152271650
  Discount Rate: 1 /  86402
```

### Recommendation

The `currentMultiplier` calculation should be reformulated to accurately represent the additional discount for seconds that have passed since the end of the last day.

I would also recommend adding fuzz tests to your test suite that isolate this function and ensure that the multiplier monotonically decreases as seconds pass (whereas, in the current implementation, there is a dramatic decrease the second after the day ends, and then the value increases until the end of the next day).

### Review

Fixed as recommended in [PR #45](https://github.com/Alongside-Finance/index-system-v2/pull/45/files). This [fuzz test](https://gist.github.com/zobront/3969f3efc514cf14ed706cae8e166fb9) has been added to the test suite, which uses the fixed implementation to ensure that key invariants hold.

## [H-01] Token accounting can be permanently broken by malicious rebalancer

The `vault` holds a `nominals` value (also known as a virtual balance) for each asset. This value represents the amount of each asset that the vault should hold per 1e18 AMKT tokens. It is an invariant of the system that `nominals[asset] * totalSupply / 1e18` should always equal the asset's balance in the contract (unless someone sends ERC20 funds directly to the contract, in which case they are ignored to maintain this invariant).

This is maintained because, when a user calls `issue()` or `redeem()`, the amount of each asset that they send or receive is calculated based on the `nominals` value, keeping the ratio in line.

Similarly, when a user calls `fullfillBounty()` to rebalance the vault, the bounty `units` represent the new `nominals` values, and the tokens are exchanged precisely to bring the vault's balances into alignment with these values.

However, during the bounty fulfillment process, there is a callback to the rebalancer:
```solidity
try Rebalancer(msg.sender).rebalanceCallback() {} catch {
    revert BountyCallbackFailed();
}
```
At this point in the function, we have already decided on the numbers of tokens that need to be sent (based on the vault's total supply) in order to keep the `nominals` value in alignment with the actual balances.

However, since the `nominals` value has not been updated at the time of this callback, if we call `issue()` or `redeem()` from this callback, we will be sending assets at the previous ratio. This will throw off the math that was intended to ensure that `nominals[asset] * totalSupply / SCALAR = asset.balanceOf(vault)`.

The result is that, when the function is completed, this invariant will no longer hold.

This will create a situation where all tokens that were rebalanced in an upward direction during this bounty will have insufficient tokens in the vault to cover the calculated amount of value. This creates two major problems:

1) These assets are permanently locked as underlying tokens of the vault. If an asset is removed from the vault (`nominals[asset] = 0`), the rebalancing process will try to send `nominals[asset] * totalSupply / SCALAR` back to the rebalancer, but the vault will not hold that many tokens, so it will fail.

2) The accounting will permanently be off, as we expect that the value of the vault's underlying tokens can be calculated using the `nominals` value of all the assets, but this will no longer be the case.

### Recommendation

Add a check that `AMKT.totalSupply()` has not changed during the callback:
```solidity
if (indexToken.totalSupply() != startingSupply) {
    revert BountyAMKTSupplyChange();
}
```

### Review

Fixed as recommended in [PR #45](https://github.com/Alongside-Finance/index-system-v2/pull/45/files).

## [H-02] If `feeScaled` is set too high in the constructor, the protocol will be bricked

When `feeScaled` is set using the `setFeeScaled()` function, we perform a check to ensure it is lower than `1e18`:
```solidity
function setFeeScaled(uint256 _feeScaled) external onlyOwner {
    if (_feeScaled > SCALAR) {
        revert AMKTVaultFeeTooLarge();
    }

    tryInflation();
    feeScaled = _feeScaled;
}
```
However, when the value is set from the constructor, there is no such check:
```solidity
constructor(
    IIndexToken _indexToken,
    address _owner,
    address _feeRecipient,
    uint256 _feeScaled
) {
    indexToken = _indexToken;
    owner = _owner;

    feeRecipient = _feeRecipient;
    feeScaled = _feeScaled;

    lastKnownMultiplier = SCALAR;
    lastKnownTimestamp = block.timestamp;
}
```
This means that it is possible for the constructor to set the value to be greater than `1e18`.

This is compensated for by performing this same check each time `computeMultiplier` is called:
```solidity
    function computeMultiplier(
        uint256 lastTrackedTimestamp,
        uint256 lastTrackedMultiplier,
        uint256 feeScaled
    )
        internal
        view
        returns (
            uint256 trackedTimestamp,
            uint256 trackedMultiplier,
            uint256 newFeeAccrued,
            uint256 currentMultiplier
        )
    {
        if (feeScaled > SCALAR) {
            revert MultiplierFeeTooHigh();
        }

        ...
}
```
However, this leads to a problem, because we will revert each time `computeMultiplier` is called.

Not only is this function called from `issue()`, `redeem()`, and `fulfillBounty()` (effectively pausing the protocol), but it's also called from within `setFeeScaled()`.

As we can see above, `setFeeScaled()` calls `tryInflation()` before it updates the value. This call to `tryInflation()` calls `multiplier()`, which calls `computeMultiplier()` which will revert because of the old value.

The result is that the protocol will be bricked and will need to be redeployed.

### Recommendation

Add a check in the constructor to ensure that `feeScaled` is being set to a number less than `1e18`:
```diff
constructor(
    IIndexToken _indexToken,
    address _owner,
    address _feeRecipient,
    uint256 _feeScaled
) {
    indexToken = _indexToken;
    owner = _owner;

    feeRecipient = _feeRecipient;
+   if (_feeScaled > SCALAR) {
+       revert AMKTVaultFeeTooLarge();
+   }
    feeScaled = _feeScaled;

    lastKnownMultiplier = SCALAR;
    lastKnownTimestamp = block.timestamp;
}
```
Additionally, once it is checked here, there is no way for `feeScaled` to ever be set greater than `1e18`, so the check in `computeMultiplier()` can be removed.

### Review

Fixed as recommended in [PR #76](https://github.com/Alongside-Finance/index-system-v2/pull/76).

## [H-03] Fees are sent to vault instead of feeRecipient

Each time AMKT tokens are issued or redeemed, or a bounty is fulfilled, a call is made to `vault.tryInflation()`. This function checks if a day has passed since the last inflation and, if it has, takes protocol fees in the form of newly minted AMKT.

```solidity
function tryInflation() public returns (uint256) {
    uint256 startingSupply = indexToken.totalSupply();

    (
        uint256 timestamp,
        uint256 trackedMultiplier,
        uint256 newFeeAccrued,
        uint256 current
    ) = multiplier();

    uint256 inflation = fmul(startingSupply, finv(newFeeAccrued)) - startingSupply;

    if (inflation > 0) {
        lastKnownMultiplier = trackedMultiplier;
        lastKnownTimestamp = timestamp;
        indexToken.mint(address(this), inflation);
    }

    return current;
}
```
These protocol fees are intended to be paid to the `feeRecipient`, a value that is set specifically for this purpose, but instead they are sent to `address(this)`.

### Recommendation

```diff
if (inflation > 0) {
    lastKnownMultiplier = trackedMultiplier;
    lastKnownTimestamp = timestamp;
-   indexToken.mint(address(this), inflation);
+   indexToken.mint(feeRecipient, inflation);
}
```

### Review

Fixed as recommended in [PR #77](https://github.com/Alongside-Finance/index-system-v2/pull/77/).

## [M-01] First mint could be frontrun to break L1 `totalSupply` calculation

In order to perform the migration for the AMKT token from L1 to L2, the following process is used:
- First, the `totalSupply` of the L1 token is minted on L2
- Then, it is sent to the L2 bridge, so that the full quantity is locked in the bridge ready to be withdrawn
- When the funds arrive to L1, the `mint()` function's logic skips the first mint, so that the `totalSupply()` stays unchanged, as implemented below

```solidity
function mint(
    address _to,
    uint256 _amount
)
    external
    virtual
    override(IOptimismMintableERC20, ILegacyMintableERC20)
    onlyBridge
{
    // ignores the first mint
    if (MIGRATED) {
        _mint(_to, _amount);
        emit Mint(_to, _amount);
    } else {
        MIGRATED = true;
    }
}
```
The intention is to ensure that the tokens deposited into the bridge on L2 are not included in the `totalSupply` calculation on L1. This logic is sound, but it assumes that the first withdrawal will be the team's withdrawal of the full `totalSupply`, which may not be the case.

To understand why, keep in mind the timing for bridging:
- Bridging from L2 to L1 (aka withdrawing) is subject to a 7 day waiting period
- Bridging from L1 to L2 (aka depositing) happens nearly instantly

As soon as the L2 contract is deployed and the funds are bridged (even before they are withdrawn), it is possible for other L1 users to burn their tokens and claim the L2 tokens.

This creates the possibility that a user could immediately burn L1 tokens to claim their L2 tokens, and then immediately withdraw all (or some portion) of those tokens back to L1. This would queue up their withdrawal transaction just minutes after the large withdrawal intended to be the initial one.

[Note that the same attack is possible by a user who calls `issue()` on L2 with the underlying tokens to create an L2 token, and then withdraws those tokens back to L1.]

After 7 days have passed, the original withdrawal by the Alongside team would become available to be triggered. However, if the team was not prompt in triggering the withdrawal right away (for example, if it was the middle of the night), the malicious user would be able to trigger their withdrawal first.

In this case, the user would receive no tokens, and all the ~30k AMKT tokens from the original withdrawal would be sent to `address(0)`, permanently messing with the L1 total supply.

### Recommendation

There are a number of ways this can be adjusted to ensure this attack is not possible. Here are the two simplest solutions:

1) The `MIGRATED` flag could be manually turned on and off by the Alongside team, rather than automatically updated after the first withdrawal.

2) Rather than using a `MIGRATED` flag to change the token's behavior, we could simply migrate the funds to a special address containing a burner contract. That contract could contain just one permissionless function (`burnAllAMKT()`) that anyone could call to burn the asset. The token contract would need to be updated with an additional function that allows this address to burn.

### Review

Fixed as recommended in [PR #82](https://github.com/Alongside-Finance/index-system-v2/pull/82).

## [M-02] Owner can steal all funds locked in bridge by changing `REMOTE_TOKEN` value

In the new `BridgedIndexToken.sol`, which the L1 contract will be upgraded to, there is a `setBridge()` function used to set the `REMOTE_TOKEN` and the `BRIDGE` addresses.
```solidity
function setBridge(
    address _remoteToken,
    address _bridge
) external onlyOwner {
    REMOTE_TOKEN = _remoteToken;
    BRIDGE = _bridge;
}
```
This function can be called by the owner at any time to update these two addresses.

The addresses are each used in important checks:
- `REMOTE_TOKEN` is checked by the Optimism bridge before allowing tokens to be minted on L1, to ensure it matches the address that was set as `remoteToken` when the L2 tokens were deposited
- `BRIDGE` is checked on the token contract to ensure that calls to `mint()` and `burn()` can only come from this address

By having the ability to update these values, the owner of the contract can steal all L2 funds locked in the bridge.

## Proof of Concept

In order to steal the funds locked in the contract, the owner would perform the following:

1) Deploy a new ERC20 token on L2, and mint themselves a quantity equal to the number of AMKT tokens locked in the bridge.

2) Deposit all these tokens into the L2 bridge, with a target of the legitimate L1 contract.

3) Wait for the 7 day waiting period so that withdrawals are permitted on L1.

4) Change the `REMOTE_TOKEN` on the L1 contract to match their newly deployed contract on L2.

5) Withdraw the tokens on L1, which will be permitted because of the matching `REMOTE_TOKEN`.

6) Change the `REMOTE_TOKEN` back to the original, and deposit the newly minted tokens back into the bridge.

7) This will convert them into the legitimate L2 AMKT tokens, which will be immediately withdrawn from the bridge, leaving the L2 bridge contract empty, so all the users with funds on L1 will be rugged.

Note that, while funds cannot be stolen by changing the `BRIDGE` value, the owner can perform a similar attack to brick in progress withdrawals, so this value should be secured as well.

### Recommendation

The `setBridge()` function should only be able to be called once, and then values should be locked. While we cannot make the values immutable (because the contract is already deployed), we can perform the following checks:

```diff
function setBridge(
    address _remoteToken,
    address _bridge
) external onlyOwner {
+   require(REMOTE_TOKEN == address(0) && BRIDGE == address(0), "values already set");
+   require(_remoteToken != address(0) && _bridge != address(0), "cannot set to zero addr");
    REMOTE_TOKEN = _remoteToken;
    BRIDGE = _bridge;
}
```

### Review

Acknowledged.

## [M-03] `proposedOwner` not reset on transfer, allowing ownership to be seized back

The ProposableOwnable.sol contract amends OpenZeppelin's Ownable Upgradeable contract to add in a two step ownership transfer process, where a new owner must be proposed and then accepted.

Because this contract inherits all the functionality of `OwnableUpgradeable.sol`, it also allows ownership to be transferred directly or renounced:

```solidity
function renounceOwnership() public virtual onlyOwner {
    _transferOwnership(address(0));
}

/**
 * @dev Transfers ownership of the contract to a new account (`newOwner`).
 * Can only be called by the current owner.
 */
function transferOwnership(address newOwner) public virtual onlyOwner {
    require(newOwner != address(0), "Ownable: new owner is the zero address");
    _transferOwnership(newOwner);
}

/**
 * @dev Transfers ownership of the contract to a new account (`newOwner`).
 * Internal function without access restriction.
 */
function _transferOwnership(address newOwner) internal virtual {
    address oldOwner = _owner;
    _owner = newOwner;
    emit OwnershipTransferred(oldOwner, newOwner);
}
```
However, as you can see, none of these functions reset the storage slot associated with `proposedOwner`.

Any address that is stored in the `proposedOwner` slot can seize ownership of the contract at any point:
```solidity
function takeOwnership(address newOwner) public virtual {
    require(
        newOwner != address(0),
        "ProposableOwnable: new owner is the zero address"
    );
    require(
        newOwner == proposedOwner,
        "ProposableOwnable: new owner is not proposed owner"
    );
    require(
        newOwner == msg.sender,
        "ProposableOwnable: this call must be made by the new owner"
    );
    _transferOwnership(newOwner);
}
```
This means that ownership can be renounced or transferred with a backdoor left to seize ownership back later.

## Proof of Concept

To accomplish this attack, an owner would:
- propose a new owner of an address they control
- renounce their ownership, or transfer it to a new owner
- later, call `takeOwnership()` from the proposed owner address to seize it back.

Here is a test that can be dropped into your test suite to demonstrate this behavior:
```solidity
function testZ__ProposedOwner() public {
    // Initialize a token that uses ProposableOwnable, setting myself to owner
    IndexToken token = new IndexToken();
    token.initialize("Fake Token", "FAKE", 1e18);
    console.log(token.owner());

    // Propose myself as the new owner.
    token.proposeOwner(address(this));

    // Renounce my ownership, apparently giving up control.
    token.renounceOwnership();
    console.log(token.owner());

    // Because I'm still in the proposedOwner slot, I can still reclaim.
    token.takeOwnership(address(this));
    console.log(token.owner());
}
```

```
Logs:
  0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496
  0x0000000000000000000000000000000000000000
  0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496
```

### Recommendation

Use OpenZeppelin's [Ownable2StepUpgradeable.sol](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/Ownable2StepUpgradeable.sol) contract instead.

### Review

Acknowledged, will fix in future release.

## [M-04] If bounty is created without all underlying tokens, accounting will be permanently thrown off

When a bounty is created, it includes a `nominal` value for each underlying token.

If the token is not going to be adjusted, the `nominal` value should equal the previous nominal amount, minus all fees that have accrued since then.

```solidity
uint256 realUnitsAtLastFeeTimestamp = fmul(
    vault.virtualUnits(token),
    trackedMultipler
);

if (realUnitsAtLastFeeTimestamp > targetUnits) {
    uint256 diff = realUnitsAtLastFeeTimestamp - targetUnits;
    uint256 underlyingAmount = fmul(diff, startingSupply);
    ....
```
This is because, at the end of rebalancing, the `nominal` value is set, and the `lastKnownMultiplier` is reset to `SCALAR`.

As an example, if we have a `nominal` for USDC of 100 (meaning 100 USDC per AMKT), but our `trackedMultplier` is 0.95, this means our `realUnits` of USDC is 95. If we create a new bounty, we need to set the `nominal` value to 95, because the `trackedMultiplier` will be reset to 1.

Since the `lastKnownMultiplier` is used across all tokens, any tokens that don't have their nominals adjusted are implicitly increasing the number of units the vault believes they have (because that value is calculated as `nominals * multiplier * totalSupply`, and we are increasing the multiplier without adjusting the others).

However, if an underlying token is not included in the bounty, it does not have new assets transferred in or out of the vault.

Then, when `vault.invokeSetNominal(nominals);` is called, it is simply skipped:
```solidity
function invokeSetNominal(
    SetNominalArgs[] calldata args
) external onlyRebalancer {
    for (uint256 i; i < args.length; i++) {
        _setNominal(args[i]);
    }
}
```
```solidity
function _setNominal(SetNominalArgs memory args) internal {
    address token = args.token;
    uint256 _virtualUnits = args.virtualUnits;

    if (_virtualUnits == 0) {
        delete nominals[token];
        _underlying.remove(token);
        return;
    }

    if (!isUnderlying(token)) {
        _underlying.add(token);
    }

    nominals[token] = _virtualUnits;
}
```
The result is that any token that is skipped is now permanently projected to have more assets in the vault than it actually has. This will create the same issues discussed in H-01, where emptying the vault of the asset is no longer possible, and all token accounting will be permanently thrown off.

### Recommendation

The `invokeSetNominal()` function should ensure that the array passed includes every asset that is included in the `_underlying` array.

### Review

Fixed as recommended in [PR #78](https://github.com/Alongside-Finance/index-system-v2/pull/78/).

Note that the fix does retain the edge case risk that one underlying token is added twice, while another is not included, but since bounties are created by the owner who will be careful about this risk, it is deemed acceptable.

## [M-05] Authority address can (maliciously or accidentally) steal user funds from the vault

Rather than using an oracle, the system relies on an `authority` address (stored on the `HashStore.sol` contract) to set the `nominals` for each asset in the vault. These nominal values are used in rebalancing the pools.

The assumption is that these values that are set reflect a rebalancing of assets that maintains approximately equal value to the current value of the vault (perhaps with some small discount to incentivize the rebalancer).

However, there are no checks to ensure this is the case.

In a reasonable case, the `authority` address may perform a simple miscalculation that leads to a rebalancer profiting greatly from their action, draining value from the vault.

In a more malicious case, the `authority` could set all the `nominals` values to 0 and immediately rebalance the pool themselves. The result would be that they would be sent all assets in the vault, leaving it empty.

### Recommendation

It may be worth implementing a more robust oracle system. Even if oracles are not used to generate these prices, they may be used to validate that the resulting value of the pool is within some threshold of the prior value.

This would protect again both user error and the risk that the `authority` keys ending up with a malicious actor who could use them to steal all the vault's funds.

### Review

Acknowledged.

## [M-06] Allowing multiple bounties to be live at once creates race condition

When the `authority` address sets up a bounty in `HashStore.sol`, they call `setHash()`, which adds the bounty hash to the `isValidHash` mapping:
```solidity
function setHash(bytes32 _hash, bool isValid) external {
    if (msg.sender != authority) revert HashStoreAuth();
    isValidHash[_hash] = isValid;
}
```
While each bounty does have a deadline field (so old bounties are unlikely to linger for longer than intended), this architecture allows for multiple bounties to be live at the same time.

In the event that multiple bounties are ever live at the same time, a race condition occurs. In other words, calling `bounty A` before `bounty B` will leave the system in a different final state than calling `bounty B` before `bounty A`.

This isn't ideal, as the goal of a bounty is for the Alongside team to dictate how the system should be moved into a rebalanced state, and it is undesirable to leave it up to a permissionless function which final state the system ends up in.

### Recommendation

Rather than using a mapping to store `isValidHash`, simply store the current hash in a `bountyHash` variable. You can then adjust the call from the rebalancer to check that:
```solidity
bytes32 bountyHash = hashBounty(bounty);
if (bountyHash != hashStore.bountyHash) revert BountyInvalidHash();
```

### Review

Fixed as recommended in [PR #79](https://github.com/Alongside-Finance/index-system-v2/pull/79).

TK to check that issues are addressed

## [M-07] Vault should have two step ownership transfer

While many of the contracts in the system inherit `ProposableOwnable.sol` for their ownership, `Vault.sol` simply tracks an `owner` in storage and has a one step `setOwner()` function.

Because the vault is (a) one of the only non-upgradeable contracts in the system and (b) has some very important `onlyOwner` functionality, it seems especially important that transfers of ownership should be handled with care.

### Recommendation

Use `ProposableOwnable.sol` or OpenZeppelin's [Ownable2Step.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable2Step.sol).

### Review

Acknowledged, will fix in future release.

## [M-08] Inflation will be overapplied if there is a time period when `totalSupply() == 0`

When any action is taken in the protocol, `tryInflation()` is called, which checks the multiplier since the last known timestamp and, if there is inflation to apply, mints new AMKT tokens as a fee on the protocol.

```solidity
function tryInflation() public returns (uint256) {
    uint256 startingSupply = indexToken.totalSupply();

    (
        uint256 timestamp,
        uint256 trackedMultiplier,
        uint256 newFeeAccrued,
        uint256 current
    ) = multiplier();

    uint256 inflation = fmul(startingSupply, finv(newFeeAccrued)) - startingSupply;

    if (inflation > 0) {
        lastKnownMultiplier = trackedMultiplier;
        lastKnownTimestamp = timestamp;

        indexToken.mint(address(this), inflation);
    }
```
As we can see, this function begins by calling `multiplier()`, which calls `Multiplier.computeMultiplier()`. This is a pure function which takes in the last tracked timestamp, the last tracked multiplier, and the fee, and uses it to compute the updated values.

In the event that `newFeeAccrued < 1e18` (which happens any time more than 1 day has passed since the latest `lastKnownTimestamp` and `fee > 0`), there should be a positive value to inflation, and the protocol's values are updated.

However, when `startingSupply == 0`, `inflation == 0` and these updates are skipped.

The correct behavior in this situation would be to update the multiplier and timestamp, but to mint no new tokens (since any percentage inflation of 0 supply should yield 0 additional tokens).

However, as the protocol is currently implemented, the entire `if` block is skipped if `inflation == 0`. As a result, the timestamp and multiplier are not updated. If, at a later date, the `totalSupply()` increases, we will use this new supply to calculate the inflation based on the full change in multiplier since the last time the timestamp was saved.

As an example:
- Let's imagine the protocol has an inflation rate of 2%.
- Due to unforeseen issues, the protocol is paused and the supply is 0 for a full year.
- After a year, user funds are moved back into the protocol.
- The first time `tryInflation()` is called, we will have a multiplier of 0.98e18 returned, and we will get instant inflation of 2%

### Recommendation

Instead of checking whether `inflation > 0`, we should check whether there are new fees accrued. We can then update the storage variables, regardless of whether new tokens are actually minted.

```diff
function tryInflation() public returns (uint256) {
    uint256 startingSupply = indexToken.totalSupply();

    (
        uint256 timestamp,
        uint256 trackedMultiplier,
        uint256 newFeeAccrued,
        uint256 current
    ) = multiplier();

-   uint256 inflation = fmul(startingSupply, finv(newFeeAccrued)) - startingSupply;

-   if (inflation > 0) {
+   if (newFeeAccrued < SCALAR) {
       lastKnownMultiplier = trackedMultiplier;
       lastKnownTimestamp = timestamp;

+      uint256 inflation = fmul(startingSupply, finv(newFeeAccrued)) - startingSupply;
+      if (inflation > 0 {
           indexToken.mint(address(this), inflation);
+      }
    }

    return current;
}
```

This has the added benefit of also saving gas, as it removes some calculations from the (most common) situation, where `tryInflation()` is called but a full day hasn't passed.

### Review

Fixed as recommended in [PR #77](https://github.com/Alongside-Finance/index-system-v2/pull/77).

## [M-09] System implicitly relies on off chain oracle

While many smart contract systems rely on on-chain oracles to determine asset prices and calculations, the rebalancing calculations for the AMKT vault is performed off-chain by the Alongside team, and uploaded in the form of a hash to the HashStore:
```solidity
function setHash(bytes32 _hash, bool isValid) external {
    if (msg.sender != authority) revert HashStoreAuth();
    isValidHash[_hash] = isValid;
}
```
There are trade offs to this methodology.

On the plus side, on-chain oracles are some of the most risky areas of any smart contract system, and removing this attack surface does minimize some forms of risk.

On the other hand, an off-chain oracle solution is not auditable or verifiable. There are risks that whatever solution the Alongside team uses is manipulated, or that the Alongside team makes an error when performing these calculations, and there is no way to assess these risks from the smart contracts alone.

### Recommendation

Similar to my advice in M-05, to create the best of both worlds, it may be worth implementing an on-chain oracle system that verifies the off-chain accounting that the Alongside team is doing. This serves the purpose of avoiding exploit risks, while also verifying that the system is robust against off-chain errors.

### Review

Acknowledged.

## [L-01] Issuer can underpay for AMKT because values are rounded down

When `issue()` is called to mint new `AMKT`, we calculate the `underlyingAmount` of each asset to be deposited by multiplying the real units (nominal units discounted for fees) by the amount of `AMKT` that is being minted.
```solidity
uint256 underlyingAmount = fmul(tokens[i].units, amount);
```
All multiplication values in Solidity are rounded down. This means that the amount of underlying assets deposited can be slightly less than the amount that should be required to mint those assets.

In general, it should be the case that rounding should happen in favor of the protocol, not the user. This means that `issue()` should round up, while `redeem()` should continue to round down.

For most tokens, this rounding will be insignificant, but there are certain high value, low decimal tokens where the impact could be more substantial. For example:
- WBTC has a value of $25k for an 8 decimal token, meaning each unit is worth 0.025 cents.
- gUSD has a value of $1 for a 2 decimal token, meaning each unit is worth 1 cent.

While these values are not substantial enough that there will be an arbitrage opportunity on Optimism, reduced fees (or migration to another L2) could lead to a situation where such an arbitrage was possible. [See this article on a Solana exploit for an example.](https://osec.io/blog/2022-04-26-spl-swap-rounding/)

### Recommendation

In the `issue()` function, add 1 unit to the `underlyingAmount` to ensure it's rounded up rather than down.

```diff
function issue(uint256 amount) external {
    vault.tryInflation();
    TokenInfo[] memory tokens = vault.realUnits(); // nominal[asset] * multiplier

    for (uint256 i; i < tokens.length; ) {
-       uint256 underlyingAmount = fmul(tokens[i].units, amount);
+       uint256 underlyingAmount = fmul(tokens[i].units, amount) + 1;
        IERC20(tokens[i].token).transferFrom(
            msg.sender,
            address(vault),
            underlyingAmount
        );

        unchecked {
            ++i;
        }
    }

    vault.invokeMint(msg.sender, amount);
}
```

### Review

Fixed as recommended in [PR #81](https://github.com/Alongside-Finance/index-system-v2/pull/81).

## [L-02] Users can dodge rebalancing costs by sandwiching rebalancer

When the vault is rebalanced according to a predefined bounty, the `nominals` will need to line up in such a way that the rebalancer will earn from profit from the trade. Otherwise, there is no incentive for them to do so.

The assumption is that this cost will be spread across AMKT holders.

However, any given holder is able to dodge this cost by sandwiching the call to `fullfillBounty()` so that the transactions are ordered:
- `redeem()` => redeem all their AMKT for underlying
- `fulfillBounty()` => the vault is rebalanced
- `issue()` => rebuy their AMKT shares for a slightly lower price

This cost will not be passed on to other users. Instead, the rebalancer will earn less than anticipated because `totalSupply` will have dropped.

While this may not be a huge deal, if it becomes a common practice it could cause problems for rebalancers, since they will not be able to rely on off-chain calculations.

### Recommendations

There doesn't appear to be an easy solution to this problem, except for to impose a delay on issuance and redemptions, or allow the rebalancer to temporarily freeze the pool in advance of performing a rebalance.

### Review

Acknowledged.

## [L-03] System cannot support atypical ERC20s

When tokens are transferred to or from the vault, the `transfer()` and `transferFrom()` functions are used.
```solidity
IERC20(tokens[i].token).transferFrom(
    msg.sender,
    address(vault),
    underlyingAmount
);
```
```solidity
function _invokeERC20(address token, address to, uint256 amount) internal {
    IERC20(token).transfer(to, amount);
}
```
Technically, the ERC20 spec dictates that tokens must return `false` in the event that a transfer fails, but it is not necessarily the case that the function will revert.

While that is the typical behavior, there are some tokens like [ZRX](https://etherscan.io/address/0xe41d2489571d322189246dafa5ebde1f4699f498#code) that do not revert on failed transfers and simply return `false`.

In the event that these tokens are included as an underlying asset in the protocol, users will be able to call `issue()` without holding any of the underlying token, and the function will pass when the transfer fails. This will result in the vault being underfunded, relative to the tracked `nominal` amount.

### Recommendation

Use Solmate's [SafeTransferLib](https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol) to ensure all ERC20 edge cases are properly handled.

### Review

Acknowledged.

## [G-01] Unnecessary ownership transfers in deploy script

In the `OPInitialMigration.sol` script, the token is initialized, and then ownership is proposed and taken by `msg.sender`:
```solidity
initalizeIndexToken(
    token,
    msg.sender,
    msg.sender,
    tokenName,
    tokenSymbol,
    _supplyCeiling
);

token.takeOwnership(msg.sender);
```
```solidity
function initalizeIndexToken(
    IndexToken token,
    address minter,
    address owner,
    string memory tokenName,
    string memory tokenSymbol,
    uint256 _supplyCeiling
) internal virtual {
    token.initialize(tokenName, tokenSymbol, _supplyCeiling);
    token.setMinter(minter);
    token.proposeOwner(owner);
}
```
However, when `token.initialize()` is called, this automatically calls `__Ownable_init()`, which transfers ownership to `msg.sender`.
```solidity
function initialize(
    string memory tokenName,
    string memory tokenSymbol,
    uint256 _supplyCeiling
) external override initializer {
    __Ownable_init();
    __Pausable_init();
    __ERC20_init(tokenName, tokenSymbol);
    __Context_init();

    supplyCeiling = _supplyCeiling;
}
```
These additional steps can be skipped to save gas on deployment.

### Recommendation

Remove the internal call and the `takeOwnership()` call, and simply `initialize()` and `setMinter()` on the token.

```diff
- initalizeIndexToken(
-     token,
-     msg.sender,
-     msg.sender,
-     tokenName,
-     tokenSymbol,
-     _supplyCeiling
- );
- token.takeOwnership(msg.sender);
+ token.initialize();
+ token.setMinter(msg.sender);
```

### Review

Acknowledged.

## [G-02] Bounty can use `lastKnownMultiplier` instead of `multiplier()` to save gas

When `fulfillBounty()` is called, we update the inflation of the vault and then get the tracked multiplier:
```solidity
vault.tryInflation();
(, uint256 trackedMultipler, , ) = vault.multiplier();
```
This `multiplier()` function performs a lot of work to generate the returned value. However, because `tryInflation()` was just called, the `trackedMultiplier` value returned will always equal the `lastKnownMultiplier` value that is inputted.

We can see this because, after `tryInflation()` is called, `lastKnownTimestamp` will either be set to `block.timestamp`, or will be a time in the past 24 hours.

When that value is passed to `computeMultiplier()` it leads to `days == 0`, which means that `newFeeAccrued == SCALAR`, therefore the following function will always return the value of `lastTrackedMultiplier`.
```
trackedMultiplier = fmul(newFeeAccrued, lastTrackedMultiplier);
```
### Recommendation

Instead of recomputing all the values in `multiplier()`, we can simply make `lastKnownMultiplier` a public variable, and call that value directly to return the amount needed to perform the bounty calculation.

### Review

Acknowledged.

## [G-03] VArray can remove `included` field to save gas

Currently, the `VerifiableArray` struct has the following elements:
```solidity
struct VerifiableArray {
    address[] elements;
    mapping(address => uint256) indexOf;
    mapping(address => bool) included;
}
```
Rather than using an additional storage slot to store `included`, this could be made more efficient by encoding whether or not the element is included within the `indexOf` field.

### Recommendation

To do this, you would change the `indexOf` mapping to `indexOfPlusOne`. That means that, for the 0th element in the array you would store 1, for the 1st element you would store 2, etc.

You can then implement a helper function called `indexOf()` that subtracts 1 from the mapping's value. In the event that the mapping's value is 0 (it is unset, and thus would not be `included`), this `indexOf()` mapping will revert.

You can look at how Curve implements `gauge_types` as an example: https://github.com/curvefi/curve-dao-contracts/blob/master/contracts/GaugeController.vy

### Review

Acknowledged.

## [G-04] `isRestricted` checks can be skipped if `msg.sender` is the minter address

In `IndexToken.sol`, there are checks when tokens are minted, burned or transferred that nobody involved in the transaction is restricted. This functionality is used to blacklist bad actors.

```solidity
    /// @notice Compliance feature to blacklist bad actors
    /// @dev Negates current restriction state
    /// @param who address
    function toggleRestriction(address who) external override onlyOwner {
        isRestricted[who] = !isRestricted[who];
        emit ToggledRestricted(who, isRestricted[who]);
    }
```
These checks extend to checking the `msg.sender` on the `mint()` and `burn()` functions, both of which are gated by the `onlyMinter` modifier, which means that `msg.sender == minter`. Since the `minter` role is an approved address, it is not necessary to check whether it is restricted.

### Recommendation

```diff
function mint(
    address to,
    uint256 amount
) external override whenNotPaused onlyMinter {
    require(
        totalSupply() + amount <= supplyCeiling,
        "will exceed supply ceiling"
    );
-   require(!isRestricted[to] && !isRestricted[msg.sender]);
+   require(!isRestricted[to]);
    _mint(to, amount);
}

function burn(
    address from,
    uint256 amount
) external override whenNotPaused onlyMinter {
-   require(!isRestricted[from] && !isRestricted[msg.sender]);
+   require(!isRestricted[from]);
    _burn(from, amount);
}
```

### Review

Acknowledged.

## [G-05] `takeOwnership()` function checks can be simplified

Currently, the `takeOwnership()` function performs the following checks to determine whether a user is allowed to take ownership:

```solidity
function takeOwnership(address newOwner) public virtual {
    require(
        newOwner != address(0),
        "ProposableOwnable: new owner is the zero address"
    );
    require(
        newOwner == proposedOwner,
        "ProposableOwnable: new owner is not proposed owner"
    );
    require(
        newOwner == msg.sender,
        "ProposableOwnable: this call must be made by the new owner"
    );
    _transferOwnership(newOwner);
}
```
To summarize:
- the inputted `newOwner` must not be `address(0)`
- the inputted `newOwner` must equal `proposedOwner`
- the inputted `newOwner` must equal `msg.sender`

This can be simplified by removing the `newOwner` value altogether, and simply checking that `msg.sender == proposedOwner`.

### Recommendation

Replace the checks in `takeOwnership()` with the following:
```solidity
function takeOwnership() public virtual {
    require(
        msg.sender == proposedOwner,
        "ProposableOwnable: sender is not proposed owner"
    );
    _transferOwnership(msg.sender);
}
```
Alternatively, replace the `ProposableOwnable.sol` contract with OpenZeppelin's [Ownable2StepUpgradeable.sol](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/access/Ownable2StepUpgradeable.sol) contract.

### Review

Acknowledged.

## [I-01] `deployVault()` function `_indexTokenOwner` argument is misnamed

The `deployVault()` function in `CoreDeploy.s.sol` script takes the following arguments:
```solidity
function deployVault(
    IIndexToken indexToken,
    address _indexTokenOwner,
    address _hashStoreOwner,
    uint256 feeScaled,
    address feeRecipient
) internal returns (Vault) {
    ...
    vault.setOwner(_indexTokenOwner);
}
```
As we can see, the `_indexTokenOwner` variable is only used to set the `vault` owner. The index token owner is set later, in the `initalizeIndexToken()` function.

The correct value is passed to the function, so there is no harm, but the name should be updated to reflect the reality of what is happening.

### Recommendation

Rename the `_indexTokenOwner` argument to `_vaultOwner`.

### Review

Acknowledged.

## [I-02] Try catch can be removed from `fulfillBounty()`

Currently, the `fulfillBounty()` function uses a `try catch` block when performing a callback to the rebalancer:
```solidity
try Rebalancer(msg.sender).rebalanceCallback() {} catch {
    revert BountyCallbackFailed();
}
```
A `try catch` block is used to ensure that a function does not revert in the case that the call reverts, and instead is moved to the `catch` block to perform that action instead.

However, in this case, the `catch` block simply reverts, so the behavior is the same.

The only difference between the two cases is that, without a `try catch` block, the error message would be the underlying error from the call, whereas in the current architecture, the error message is the generic `BountyCallbackFailed()`.

### Recommendation

```diff
- try Rebalancer(msg.sender).rebalanceCallback() {} catch {
-    revert BountyCallbackFailed();
- }
+ Rebalancer(msg.sender).rebalanceCallback();
```

### Review

Acknowledged.
