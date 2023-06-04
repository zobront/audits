<table>
    <tr><th></th><th></th></tr>
    <tr>
        <td><img src="https://deepdao-uploads.s3.us-east-2.amazonaws.com/assets/dao/logo/dhedge.jpeg" width="250" height="250" /></td>
        <td>
            <h1>dHEDGE Audit Report</h1>
            <h2>MTA Token Buyback</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: May 29 to June 1, 2023</p>
        </td>
    </tr>
</table>

# About **dHEDGE**

dHEDGE is an asset management protocol that facilitates a censorship-resistant and non-custodial connection between individuals seeking to allocate funds and asset managers.

The MTA Token Buyback is a set of contracts that allow users to burn their MTA tokens (on L1 or L2) and redeem them for MTy tokens on L2, following [dHEDGE's acquisition of mStable](https://forum.mstable.org/t/mip-33-dhedge-acquisition-of-mstable/1017).

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

The [dhedge/buyback-contract](https://github.com/dhedge/buyback-contract) repository was audited at commit [de89fbdf98c439fa659ff3ed31118be83fc91005](https://github.com/dhedge/buyback-contract/tree/de89fbdf98c439fa659ff3ed31118be83fc91005).

The following contracts were in scope:
- src/L1Comptroller.sol
- src/L2Comptroller.sol

After completion of the fixes, [PR #17](https://github.com/dhedge/buyback-contract/pull/17) was reviewed.

# Summary of Findings

| ID     | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [H-01] | User can receive too few tokens when L2Comptroller is unpaused | High | ✓ |
| [M-01] | Assertion that claimed <= burned should come after tokens have been claimed | Medium | ✓ |
| [M-02] | Possible reentrancy attack vector when buying back tokens from L1 | Medium | ✓ |
| [L-01] | Being set as receiver during L1 burn does not guarantee receiving L2 tokens | Low | ✓ |
| [L-02] | When L2Comptroller is low on funds, large claims will fail while small claims will succeed | Low | ✓ |
| [G-01] | whenNotPaused modifier can be removed from claimAll() to save gas | Gas | ✓ |
| [N-01] | `tokenPrice()` Manipulation Analysis | Non-Issue | - |

# Detailed Findings

## [H-01] User can receive too few tokens when L2Comptroller is unpaused

When MTA tokens are burned on L1 to generate MTy tokens on L2, the message is passed using Optimism's Cross Domain Messenger contract.

If the ultimate call to `buyBackFromL1()` fails, the Cross Domain Messenger contains functionality to set the message as `failed` so it can be replayed:
```solidity
xDomainMsgSender = _sender;
bool success = SafeCall.callWithMinGas(_target, _minGasLimit, _value, _message);
xDomainMsgSender = Constants.DEFAULT_L2_SENDER;

if (success) {
    successfulMessages[versionedHash] = true;
    emit RelayedMessage(versionedHash);
} else {
    failedMessages[versionedHash] = true;
    emit FailedRelayedMessage(versionedHash);
}
```
This `failed` state would occur in any situation where the call to `buyBackFromL1()` reverts. One example of such a situation would be if the `L2Comptroller` contract is in a paused state.

We can imagine that, in such a state, a user makes two deposit transactions. The first has `totalBurntAmount = X`, while the second has `totalBurntAmount = X + N`, where `N` is the amount of MTA deposited in the second transaction.

Later, the `L2Comptroller` contract is unpaused. But, at some point (either immediately or later) it runs out of MTy tokens to distribute.

When `buyBackFromL1()` is called, the function is expected to:
- set `l1BurntAmountOf` to the new value
- try to call `this._buyBack()` to transfer the tokens
- since there are no tokens to transfer, do not update `claimedAmountOf`

The problem is that the two transactions can be called in the wrong order. Because there is no check that `l1BurntAmountOf` is monotonically increasing, the second transaction will overwrite the `l1BurntAmountOf` of the first:
```solidity
// `totalAmountClaimed` is of the `tokenToBurn` denomination.
uint256 totalAmountClaimed = claimedAmountOf[l1Depositor];

// The cumulative token amount burnt and claimed against on L2 should never be less than
// what's been burnt on L1. This indicates some serious issues.
assert(totalAmountClaimed <= totalAmountBurntOnL1);

// The difference of both these variables tell us the claimable token amount in `tokenToBurn`
// denomination.
uint256 burnTokenAmount = totalAmountBurntOnL1 - totalAmountClaimed;

if (burnTokenAmount == 0) {
    revert ExceedingClaimableAmount(l1Depositor, 0, 0);
}

// Store the new total amount of tokens burnt on L1 and claimed against on L2.
l1BurntAmountOf[l1Depositor] = totalAmountBurntOnL1;
```
The last time it was claimed was before these two transactions, so `totalAmountClaimed < X`, and all checks pass. When the second transaction is called, `l1BurntAmountOf` is set to `X + N`. Then, when the first transaction is called, `l1BurntAmountOf` is set to `X`.

In the Bedrock system, this call to the Cross Domain Messenger to replay old transactions in the wrong order can be performed by anyone, so a malicious user could perform this action on behalf of our innocent user.

The result is that, when the user calls `claim()` or `claimAll()`, they will only receive `X` tokens, instead of the `X + N` they are entitled to.

### Proof of Concept

Here is a test that can be dropped into the repo to reproduce this behavior. You can run it with `forge test -vvv --match-test testOutOfSyncBrickedFunds`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/L1Comptroller.sol";
import "src/L2Comptroller.sol";
import {IERC20Burnable} from "../src/interfaces/IERC20Burnable.sol";
import {ICrossDomainMessenger} from "../src/interfaces/ICrossDomainMessenger.sol";
import {IPoolLogic} from "../src/interfaces/IPoolLogic.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/interfaces/IERC20Upgradeable.sol";

library AddressAliasHelper {
    uint160 constant offset = uint160(0x1111000000000000000000000000000000001111);

    function applyL1ToL2Alias(address l1Address) internal pure returns (address l2Address) {
        unchecked {
            l2Address = address(uint160(l1Address) + offset);
        }
    }
}

interface IMTy is IERC20Upgradeable {
    function totalSupply() external view returns (uint);
}

contract OutofSyncBrickedFundsTest is Test {
    L2Comptroller l2c = L2Comptroller(0x3509816328cf50Fed7631c2F5C9a18c75cd601F0);
    ICrossDomainMessenger l2xdm = ICrossDomainMessenger(0x4200000000000000000000000000000000000007);
    IMTy mty = IMTy(0x0F6eAe52ae1f94Bc759ed72B201A2fDb14891485);

    function testOutOfSyncBrickedFunds() public {
        vm.createSelectFork("INSERT_RPC_URL");

        // simulate a situation where L2Comptroller has no funds & is paused
        address user = makeAddr("user");
        uint bal = mty.balanceOf(address(l2c));
        vm.prank(address(l2c));
        mty.transfer(address(1), bal);
        address owner = l2c.owner();
        vm.prank(owner);
        l2c.pause();

        // send two txs, one for 1e18 totalBurned and one for 2e18 totalBurned
        address aliasedXDM = AddressAliasHelper.applyL1ToL2Alias(l2xdm.l1CrossDomainMessenger());
        uint nonce100 = uint(keccak256(abi.encode("nonce100")));
        uint nonce200 = uint(keccak256(abi.encode("nonce200")));

        vm.startPrank(aliasedXDM);
        l2xdm.relayMessage(
            0x3509816328cf50Fed7631c2F5C9a18c75cd601F0, // L1Comptroller
            0x3509816328cf50Fed7631c2F5C9a18c75cd601F0, // L2Comptroller
            abi.encodeWithSignature(
                "buyBackFromL1(address,address,uint256)",
                user,
                user,
                1e18
            ),
            nonce100
        );
        l2xdm.relayMessage(
            0x3509816328cf50Fed7631c2F5C9a18c75cd601F0, // L1Comptroller
            0x3509816328cf50Fed7631c2F5C9a18c75cd601F0, // L2Comptroller
            abi.encodeWithSignature(
                "buyBackFromL1(address,address,uint256)",
                user,
                user,
                2e18
            ),
            nonce200
        );
        vm.stopPrank();

        // unpause the L2Comp contract
        vm.prank(owner);
        l2c.unpause();

        // execute the 2e18 transaction first, and then the 1e18 transaction
        // in bedrock, anyone can call this, but on old OP system we need to prank aliased XDM
        // these will be saved as unclaimed on contract because there are no funds to pay
        vm.startPrank(aliasedXDM);
        l2xdm.relayMessage(
            0x3509816328cf50Fed7631c2F5C9a18c75cd601F0, // L1Comptroller
            0x3509816328cf50Fed7631c2F5C9a18c75cd601F0, // L2Comptroller
            abi.encodeWithSignature(
                "buyBackFromL1(address,address,uint256)",
                user,
                user,
                2e18
            ),
            nonce200
        );
        l2xdm.relayMessage(
            0x3509816328cf50Fed7631c2F5C9a18c75cd601F0, // L1Comptroller
            0x3509816328cf50Fed7631c2F5C9a18c75cd601F0, // L2Comptroller
            abi.encodeWithSignature(
                "buyBackFromL1(address,address,uint256)",
                user,
                user,
                1e18
            ),
            nonce100
        );
        vm.stopPrank();

        // add funds to the contract
        deal(address(mty), address(l2c), 10e18);

        // user calls claimAll
        vm.prank(user);
        l2c.claimAll(user);

        // even though the user should have 2e18 worth of MTy tokens
        // they actually only have ~1e18 worth
        // their `l1BurntAmountOf` is 1e18 as well
        assertApproxEqAbs(l2c.convertToTokenToBurn(mty.balanceOf(user)), 1e18, 100);
        assertEq(l2c.l1BurntAmountOf(user), 1e18);
    }
}
```
### Recommendation

Add a check in `buyBackFromL1()` to ensure that `l1BurntAmountOf` is monotonically increasing:
```diff
function buyBackFromL1(
    address l1Depositor,
    address receiver,
    uint256 totalAmountBurntOnL1
) external whenNotPaused {
    ...
+   if (totalAmountBurntOnL1 < l1BurntAmountOf[l1Depositor]) {
+      revert DecreasingBurntAmount;
+   }
    l1BurntAmountOf[l1Depositor] = totalAmountBurntOnL1;
    ...
}
```

### dHEDGE Response

We were unaware of the fact that the Cross Domain Messenger contains functionality to set the message as `failed` so it can be replayed. We will take the necessary step of adding a check in `buyBackFromL1()` to ensure that `l1BurntAmountOf` is monotonically increasing.

### Review

Fixed in [PR #17](https://github.com/dhedge/buyback-contract/pull/17/) as recommended.

## [M-01] Assertion that claimed <= burned should come after tokens have been claimed

In both the `claim()` and `buyBackFromL1()` functions, there is the following assertion:
```solidity
assert(totalAmountClaimed <= totalAmountBurntOnL1);
```
This is used to ensure that the most important invariant of the system is always upheld. It is also used so that, if a user is able to trigger this state, an off chain guardian can pause the contract so the cause can be investigated.

Currently, this check exists near the beginning of the functions, before `claimedAmountOf[msg.sender]` is incremented.

However, this opens up the possibility that new claims might break this invariant, and the system would have no way of catching them. Instead, the invariant should be upheld after all new claims are made, so we can be sure that this invariant cannot be broken.

### Recommendation

`claimedAmountOf[msg.sender]` is incremented in the `claim()` and `buyBackFromL1()` functions. In both cases, the assertion should be moved to after the value is updated.

- In `buyBackFromL1()`, it should live after the `try catch` block.
- In `claim()`, it should live right after `claimedAmountOf` is incremented, before the call to `_buyBack()`.

Note: This fix will also address the reentrancy risk in #12.

### dHEDGE Response

The solution proposed is easy to implement and doesn't change any of our earlier assumptions. This will be fixed.

### Review

Fixed in [PR #17](https://github.com/dhedge/buyback-contract/pull/17/) as recommended.

## [M-02] Possible reentrancy attack vector when buying back tokens from L1

When tokens are burned on L1 and claimed on L2, we always increment the `l1BurntAmountOf`. We then attempt to transfer the tokens to the user and — if it is successful — we increment `claimedAmountOf`.

```solidity
...

l1BurntAmountOf[l1Depositor] = totalAmountBurntOnL1;

// The reason we are using try-catch block is that we want to store the `totalAmountBurntOnL1`
// regardless of the failure of the `_buyBack` function. This allows for the depositor
// to claim their share on L2 later.
try this._buyBack(receiver, burnTokenAmount) returns (
    uint256 buyTokenAmount
) {
    // Updating the amount claimed against the tokens burnt by the `l1Depositor`.
    claimedAmountOf[l1Depositor] += burnTokenAmount;
    ...
}
```
This breaks the Checks-Effects-Interactions pattern commonly used to avoid reentrancy risk.

If a caller were to be able to take control flow during the `_buyBack()` function, this would lead to an exploit vector that could be used to steal all funds:
- If the contract is paused, a user sends many L1 transactions, which are queued up in the Cross Domain Messenger
- They call `buyBackFromL1()`, which increments `l1BurntAmountOf` and calls `_buyBack()`
- During `_buyBack()`, they take back control flow and trigger their next Cross Domain Messenger transaction, which calls `buyBackFromL1()` again and passes all checks
- Each of these transactions passes all checks to send more funds, because the `claimedAmountOf` has not been incremented yet
- Finally, all transactions are completed, each of which sends the user `buyTokenAmount` tokens and increments `claimedAmountOf` by `burnTokenAmount` (pushing it far above `l1BurntAmountOf`)

Fortunately, at the moment, it appears that this attack is not possible because the token used does not have callbacks to the receiver, so there is no way for the user to gain control flow during `_buyBack()`. However, it does have an external call (to the mStable `factory` contract). With this in mind, there are two situations to consider:

1) This code CANNOT be used in the future with ERC777 tokens. If it is, the receiver is checked, which makes this vulnerability easily exploitable.

2) The mStable factory logic cannot be changed to include a callback to the receiver. Since the factory is upgradeable, it is worth being cautious about this. Currently, the `_beforeTokenTransfer()` function makes a call to `factory.receiverWhitelist(receiver)`. If the factory logic included any call to the receiver as a part of this check, it would open up the vulnerability.

### Recommendation

As long as the two risks above do not come to pass, there is no need to make changes to the code. However, given that one of the risks is based on assumptions about external upgradeable code not changing, it may be worth being sure.

If you do want to make the code robust against those two scenarios you have three options.

Option 1: Move the assertion that `claimed <= burned` to after `claimedAmountOf` has been incremented, as laid out in #15.

Option 2: Add a `nonReentrant` modifier to the `_buyBack()` function.

Option 3: Increment `claimedAmountOf` before calling `_buyBack()` (ensuring the state is correct during the external call), and then decrement it in the error cases.

### dHEDGE Response

Usage of these contracts with ERC777 or upgradeable tokens is not recommended at least in its current state. The assumptions we made while creating these contracts were for non-upgradeable ERC20 tokens. We have moved the assertion statement `claimed <= burned` to after `claimedAmountOf` has been incremented (the suggested option 1).

However, we re-iterate that these contracts not be used for ERC777 tokens or upgradeable tokens without changes to mitigate the unique issues associated with them.

### Review

Fixed in [PR #17](https://github.com/dhedge/buyback-contract/pull/17/) with Option 1.

## [L-01] Being set as receiver during L1 burn does not guarantee receiving L2 tokens

When a user burns a token on L1 to receive it on L2, they call the following function:
```solidity
function buyBack(
    address receiver,
    uint256 burnTokenAmount
) external whenNotPaused whenL2ComptrollerSet {
    ...
}
```
The function takes in an amount of tokens to burn, as well as a receiver for the MTy tokens on L2.

This may seem to be guaranteeing that the `receiver` will be the address to receive the tokens on L2. We could imagine a situation where a user calls this function on L1 with another user's address set to `receiver` and is paid in exchange for doing this.

However, in the event that the L2 contract is out of funds (or reverts for some other reason), the claim will be saved for the user to claim later on. This claim can only be made by the `msg.sender` of the original L1 transaction.

Further, when they call the `claim()` or `claimAll()` function, they are able to input a new receiver and send the funds to them instead:
```solidity
function claimAll(address receiver) external whenNotPaused {
    // The difference between burnt amount and previously claimed amount gives us
    // the claimable amount in `tokenToBurn` denomination.
    claim(
        receiver,
        l1BurntAmountOf[msg.sender] - claimedAmountOf[msg.sender]
    );
}
```
The result is that the user who expected to receive the MTy tokens may not, in fact, receive them.

### Recommendation

It seems that making the guarantee that the `receiver` set on L1 would receive the tokens on L2 would require changing the architecture of the system pretty substantially.

My recommendation is just to make clear to users that this `receiver` is not a guarantee, and in the event that the L2 transaction reverts, the user will have the opportunitiy to select a new `receiver`.

### dHEDGE Response

We will look at steps we can take to make the user fully understand this risk in the event that a user's L2 transaction reverts. This feature was originally intended for users using Gnosis Safe smart contract wallets as deploying the same safe on 2 networks is extremely difficult. They can either call the `claimAll()` function on L2 or trigger another buyback on L1 with 0 amount which in effect does the same thing as the former method. The second way (triggering with 0 amount) might be useful in case the user has used a Gnosis Safe wallet.

### Review

Confirmed, this logic makes sense and as long as it is communicated to users, is completely safe.

## [N-01] When L2Comptroller is low on funds, large claims will fail while small claims will succeed

When a user claims tokens on L2 (whether through `buyBackFromL1()`, `buyBack()`, `claim()` or `claimAll()`), the tokens are transferred with the following logic:
```solidity
// Transfer the tokens to the caller.
// We are deliberately not checking if this contract has enough tokens as
// this would have the desired impact in case of low buy token balance anyway.
IERC20Upgradeable(address(tokenToBuy)).safeTransfer(
    receiver,
    buyTokenAmount
);
```
It is expected that, at times, the contract will not have sufficient tokens to perform this transfer, as it will be reloaded manually by the team. However, as the comment states, a revert in the case of insufficient tokens is the desired behavior, as this will cause the claim to fail when it should, and will be caught by the `try catch` block in the case of a transaction from L1.

However, this behavior can revert on large claims, while smaller claims continue to succeed.

It seems that, in the event that a user requests X tokens and there are only Y in the contract (where Y < X), it would be preferable for the user to receive Y tokens instead.

### Recommendation

`buyTokenAmount` can be adjusted to be the lower amount of the `buyTokenAmount` and the balance of the contract.

```diff
function _buyBack(
    address receiver,
    uint256 burnTokenAmount
) external returns (uint256 buyTokenAmount) {

    ...
    buyTokenAmount = (burnTokenAmount * exchangePrice) / tokenToBuyPrice;
+   uint contractBalance =  IERC20Upgradeable(address(tokenToBuy)).balanceOf(address(this));
+   buyTokenAmount = buyTokenAmount > contractBalance ? contractBalance : buyTokenAmount;

    // Transfer the tokens to the caller.
    // We are deliberately not checking if this contract has enough tokens as
    // this would have the desired impact in case of low buy token balance anyway.
    IERC20Upgradeable(address(tokenToBuy)).safeTransfer(
        receiver,
        buyTokenAmount
    );

    ...
```

This would require some changes to ensure the updates of `claimedAmountOf` were for `convertToTokenToBurn(buyTokenAmount)`, and to send back the difference to users calling `buyBack()`, but seems to be worthwhile to ensure users claim in the order expected.

### dHEDGE Response

Earlier, that method did indeed transfer whatever amount was there in the contract (the solution you described). However, I decided against it in the final implementation because I believe the user should get the exact amount that they were promised first (either using our UI or directly interacting with the contracts after having done calculations). Users might panic due to getting lesser amount and it's not trivial to find out if any more tokens can be claimed (from user's POV).

### Review

The team has considered their options and decided the current behavior is preferable. This is a reasonable decision, and the current behavior is safe.

## [G-01] whenNotPaused modifier can be removed from `claimAll()` to save gas

The `claimAll()` function contains the `whenNotPaused` modifier:
```solidity
function claimAll(address receiver) external whenNotPaused {
    // The difference between burnt amount and previously claimed amount gives us
    // the claimable amount in `tokenToBurn` denomination.
    claim(
        receiver,
        l1BurntAmountOf[msg.sender] - claimedAmountOf[msg.sender]
    );
}
```
However, this function calls `claim()`, which already contains this modifier:
```solidity
function claim(
    address receiver,
    uint256 burnTokenAmount
) public whenNotPaused {
    ...
}
```
We can therefore remove the modifier from the `claimAll()` function to save a small amount of gas, while keeping the contract's behavior identical.

### Recommendation

```diff
- function claimAll(address receiver) external whenNotPaused {
+ function claimAll(address receiver) external {
     // The difference between burnt amount and previously claimed amount gives us
     // the claimable amount in `tokenToBurn` denomination.
     claim(
         receiver,
         l1BurntAmountOf[msg.sender] - claimedAmountOf[msg.sender]
     );
 }
```

### dHEDGE Response

This will be fixed.

### Review

Fixed in [PR #17](https://github.com/dhedge/buyback-contract/pull/17/) as recommended.

## [N-01] `tokenPrice()` Manipulation Analysis

If the price returned by `tokenPrice()` can be manipulated, then the `_buyBack()` function will provide the user with the wrong number of MTy tokens on L2.

Fortunately, there is protection against `tokenPrice()` falling by more than 0.1% (to catch depegs), which prevents a manipulation down from being performed. This is the type of manipulation that would be profitable to the attacker, as it would lead to them receiving extra MTy tokens on L2.

However, even manipulating the price up could be harmful, as a user with a claim stuck in the Optimism Cross Domain Messenger could have that claim replayed by any user, which allows it to be sandwiched inside a price manipulation attack to give the user fewer MTy tokens than they deserve.

In order to determine whether this risk exists, I analyzed the `tokenPrice()` function.
- It calls `poolManagerLogic.totalFundValue()` to get the total value of the pool, which sums the balances of all the tokens supported by the pool.
- This total fund value is divided by the total supply of tokens to get the price per token.

`totalSupply()` seems to be incremented and decremented only in the inherented OpenZeppelin contract, which performed these updates safely.

There are two ways that the `totalFundValue` can be changed: (a) make the pool hold a different number of underlying token without MTy total supply adjusting accordingly or (b) mess with the underlying prices of the tokens.

For the first, the only way to do this would be to donate tokens for free to the contract. This would be a potential attack if the first depositer were able to do it, but it is protected on the current contract because (a) any dip in token price of more than 0.1% would be rejected and (b) there is already $2mm USD in the contract, so it would be exorbitantly expensive (and not profitable) to perform this manipulation. As a result, this attack does not seem to be a threat.

In terms of the second option, in order to determine whether the asset prices are safe, it is necessary to look at each of the underlying assets, the oracle used for each, and whether it is prone to manipulation.

Supported Asset: [USDC/sUSD Pool](https://optimistic.etherscan.io/address/0xd16232ad60188b68076a235c65d692090caba155)
- Oracle: 0x5212797D402c11fFF8F19C4BF7Eb311A122521d9
- Analysis: Uses Velodrome pair totalSupply() and getReserves() to calculates the value using the [Fair LP Pricing](https://blog.alphaventuredao.io/fair-lp-token-pricing/) formula. As long as Velodrome returns the correct values, this shouldn't be able to be manipulated.

Supported Asset: [sUSD](https://optimistic.etherscan.io/address/0x8c6f28f2f1a3c87f0f938b96d27520d9751ec8d9)
- Oracle:  0x5298aAA21a50DBF21E3C82197857fBE84821EAD3
- Analysis: Price is determined by getting the USDC price from Chainlink, getting the sUSD to USDC price from the Velodrome TWAP (which is assumed to be safe), and using these to determine an sUSD price.

Supported Asset: [USDC](https://optimistic.etherscan.io/address/0x7f5c764cbc14f9669b88837ca1490cca17c31607)
- Oracle: 0x16a9FA2FDa030272Ce99B29CF780dFA30361E0f3
- Analysis: Uses a Chainlink oracle directly.

Supported Asset: [USDy](https://optimistic.etherscan.io/address/0x1ec50880101022c11530a069690f5446d1464592)
- Oracle: 0x3727181ED49576bB5E00CC04C788E98C563Cc649
- Analysis: This uses the same `tokenPrice()` formula we are investigating, but with its own separate list of Supported Assets. In order to determine if this can be manipulated, we need to investigate whether any of the sublist of Supported Assets can be manipulated.

Sub-Supported Asset: [USDC/sUSD Pool](https://optimistic.etherscan.io/address/0xd16232ad60188b68076a235c65d692090caba155)
- Already addressed above.

Sub-Supported Asset: [USDC/MAI Pool](https://optimistic.etherscan.io/address/d62c9d8a3d4fd98b27caaefe3571782a3af0a737)
- Oracle: 0x454a70B8d766eF1F8d6cF848aff6e4Ea4D5D6425
- Analysis: Same analysis as the USDC/sUSD Pool, but with MAI as one of the underlying tokens.

Sub-Supported Asset: [sUSD](https://optimistic.etherscan.io/address/0x8c6f28f2f1a3c87f0f938b96d27520d9751ec8d9)
- Already addressed above.

Sub-Supported Asset: [USDC](https://optimistic.etherscan.io/address/0x7f5c764cbc14f9669b88837ca1490cca17c31607)
- Already addressed above.

Sub-Supported Asset: [VELO](https://optimistic.etherscan.io/address/3c8b650257cfb5f272f799f5e2b4e65093a11a05)
- Oracle: 0xC5E24F77F7da75Ef67610ae624f9edc0CCCC7816
- Analysis: Same analysis as the sUSD token, except using the TWAP for the USDC/VELO pool.

Sub-Supported Asset: [OP](https://optimistic.etherscan.io/address/4200000000000000000000000000000000000042)
- Oracle: 0x0D276FC14719f9292D5C1eA2198673d1f4269246
- Analysis: Uses a Chainlink oracle directly.

Sub-Supported Asset: [MAI](https://optimistic.etherscan.io/address/dfa46478f9e5ea86d57387849598dbfb2e964b02)
- Oracle: 0xECAF977A599cD94c71e7292BA0c9cEA9eA227d2a
- Analysis: Same analysis as the sUSD and VELO tokens, except using the TWAP for the USDC/MAI pool.
