<table>
    <tr>
        <td><img src="https://pbs.twimg.com/profile_images/1467601380567359498/oKcnQo_S_400x400.jpg" width="250" height="250" /></td>
        <td>
            <h1>Nouns Agora Audit Report</h1>
            <h2>Alligator (Liquid Delegator)</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: March 18 to 21, 2023</p>
        </td>
    </tr>
</table>

# About **Alligator**

Agora is the hub for Nouns governance participants to view delegates and their past activities, share their views, and more.

Alligator is a liquid delegation primative that allows users to pool and subdelegate their votes based on detailed criteria, which will be deployed first for NounsDAO and then opened up to other DAOs.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

The [voteagora/liquid-delegator](https://github.com/voteagora/liquid-delegator) repository was audited at commit [38c41dd0c09b41f4597175cbd31e07e859fc3e2f](https://github.com/voteagora/liquid-delegator/tree/38c41dd0c09b41f4597175cbd31e07e859fc3e2f).

The following contracts were in scope:
- src/Alligator.sol
- src/Proxy.sol
- src/v2/AlligatorV2.sol
- src/v2/ProxyV2.sol
- src/utils/ENSHelper.sol

After completion of the fixes, the [c532d3e9e52e08c5a43d13cee3de8865fa143e00](https://github.com/voteagora/liquid-delegator/tree/c532d3e9e52e08c5a43d13cee3de8865fa143e00) commit was reviewed.

# Summary of Findings

| ID     | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [C-01] | Malicious user can have Proxy sign arbitrary data | Critical |  ✓ |
| [H-01] | Alligator gives gas refunds but does not receive gas refunds | High |  ✓ |
| [H-02] | Gas refunds can be abused by batching transactions | High |  ✓ |
| [L-01] | Check for array length equality in subDelegateAllBatched | Low | ✓ |
| [L-02] | User may unexpectedly perform refund transaction without getting refund | Low |   |
| [G-01] | Cache array lengths before loops | Gas | ✓ |
| [G-02] | Slight gas savings by rearranging validate() function | Gas | ✓ |

# Detailed Findings

## [C-01] Malicious user can have Proxy sign arbitrary data

ProxyV2.sol implements EIP1271, where `isValidSignature()` can be called with a hash and a signature, and returns 0x1626ba7e if the contract considers the signature valid.

This is done by calling `Alligator.isValidProxySignature()`. In the case where a signature is included as an argument, this function checks two things:
1) `ECDSA.recover` verifies that the signature is valid, and return the address of the user who signed it.
2) That address is passed to `validate()` along with the authority chain (which is decoded from the signature data passed) to ensure that the signing user has permission to sign on behalf of the Proxy.

```solidity
function isValidProxySignature(
    address proxy,
    Rules calldata proxyRules,
    bytes32 hash,
    bytes calldata data
) public view returns (bytes4 magicValue) {
    if (data.length > 0) {
        (address[] memory authority, bytes memory signature) = abi.decode(data, (address[], bytes));
        address signer = ECDSA.recover(hash, signature);
        validate(proxyRules, signer, authority, PERMISSION_SIGN, 0, 0xFE);
        return IERC1271.isValidSignature.selector;
    }
    return validSignatures[proxy][hash] ? IERC1271.isValidSignature.selector : bytes4(0);
}
```
**The problem is that the authority chain is never verified. A malicious user can pass any authority chain they would like into the signature field, which allows them to set themselves as `authority[0]` and bypass all checks.**

In the case where `authority.length > 1`, the `validate()` function checks the subDelegation rules for each step of the chain, and therefore we can't pass a fraudulent chain.

However, in the case where `authority.length == 1`, there is no check. In this situation, I can:
- Pass a "signature" to the Proxy that consists of my own address as the authority chain, and my own signature on the data
- It will verify that I am the signer of the data
- It will run `validate()`, which will simply validate that signing is allowed based on the Proxy rules, and then return early because `sender == authority[0]`
- `isValidProxySignature()` will return `IERC1271.isValidSignature.selector`, which will be returned by `isValidSignature()`, representing an approval that the Proxy contract is signing the data

## Proof of Concept

Here is a test that can be dropped into `AlligatorV2.t.sol` to show this attack.

```solidity
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

function testZach__SigningBug() public {
    // create an address from private key = 0x01 that should have no authority
    uint PRIVATE_KEY = 1;
    address signer = vm.addr(PRIVATE_KEY);

    // sign any message with that private key
    bytes32 hash = keccak256(abi.encodePacked("i can make you sign anything"));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, hash);
    bytes memory signature = abi.encodePacked(r, s, v);

    // set the authority chain to be only my own address
    address[] memory authority = new address[](1);
    authority[0] = signer;

    // create the signature data, which consists of authority chain and signature
    bytes memory digest = abi.encode(authority, signature);

    // confirm that the proxy will accept the signature
    assertEq(IERC1271(root).isValidSignature(hash, digest), IERC1271.isValidSignature.selector);
}
```

## Recommendation

There should be a check in `isValidProxySignature()` to confirm that the authority chain is valid. This can be accomplished by checking that:
```solidity
if (proxy != proxyAddress(authority[0], proxyRules)) revert InvalidAuthorityChain;
```

### Review

Fixed as suggested in both `AlligatorV2.sol` and `Alligator.sol` in PR #14.

## [H-01] Alligator gives gas refunds but does not receive gas refunds

The `AlligatorV2.sol` contract has a function `castRefundableVotesWithReasonBatched()` which tracks the gas used and provides a refund to the user. This mirrors the functionality used by `NounsLogicV2` to provide voting refunds.

However, while Alligator can provide refunds, there's no way for it to be refunded by the underlying DAO. This is because Nouns (for example) requires a call to `castRefundableVote()` in order to provide a refund, but Alligator simply calls `castVotesWithReasonBatched()` which calls `Nouns.castVoteWithReason()`:

```solidity
function castRefundableVotesWithReasonBatched(
    Rules[] calldata proxyRules,
    address[][] calldata authorities,
    uint256 proposalId,
    uint8 support,
    string calldata reason
) external whenNotPaused {
    uint256 startGas = gasleft();
    castVotesWithReasonBatched(proxyRules, authorities, proposalId, support, reason);
    _refundGas(startGas);
}
```

```solidity
function castVotesWithReasonBatched(
    Rules[] calldata proxyRules,
    address[][] calldata authorities,
    uint256 proposalId,
    uint8 support,
    string calldata reason
) public whenNotPaused {
    address[] memory proxies = new address[](authorities.length);
    address[] memory authority;
    Rules memory rules;

    for (uint256 i; i < authorities.length; ) {
        authority = authorities[i];
        rules = proxyRules[i];
        validate(rules, msg.sender, authority, PERMISSION_VOTE, proposalId, support);
        proxies[i] = proxyAddress(authority[0], rules);
        INounsDAOV2(proxies[i]).castVoteWithReason(proposalId, support, reason);

        unchecked {
            ++i;
        }
    }

    emit VotesCast(proxies, msg.sender, authorities, proposalId, support);
}
```
The result is that Alligator will only refund users out of its own balance, but will not be refunded by the DAO.

## Recommendation

Refactor `castRefundableVotesWithReasonBatched()` to use the `castRefundableVote()` entry point to the `governor` contract, so that it receives a refund before passing along the refund to the user.

### Review

Fixed in PR #14.

Nouns gas refunds are sent to `tx.origin` and not `msg.sender`, which allows Alligator to remove all refund functionality and simply call the `castRefundableVoteWithReason()` function to have the refund sent to the caller.

An additional safety measure was added to the proxy to account for other protocols that send gas refunds to `msg.sender`. To account for this case, a `receive()` function was added to the proxy so that, if funds are received from the `governor`, they are forwarded along to the caller.

## [H-02] Gas refunds can be abused by batching transactions

The refund mechanism assumes a `REFUND_BASE_GAS` value of 36k to account for the overhead gas that occurs outside of the tracked gas. Specifically, this accounts for the 20k gas to kick off the transaction, 7k for the ETH transfer, and other gas spent before `startGas` or within the `_refundGas()` function.

This is a fixed amount, which means that if less than 36k of overhead gas is used, the user is refunded more than the amount spent.

If multiple calls to `castRefundableVotesWithReasonBatched()` are batched into a single transaction, the actual gas spent per transaction will be lower than expected because:

1) The 20k transaction overhead will only be spent once, so will result in 20k gas profit each subsequent transaction.
2) The address for receiving ETH will be "warm", which will save an additional ~2.5k gas per transaction

A situation where a large number of these calls are batched could easily be created by a user splitting their Nouns across multiple accounts, and setting up different delegation paths for each. In this situation, separate calls could be made to vote with each Nouns and with each proposal.

## Proof of Concept

To prove the exploit, I created a test where two users delegate to Alice, and rather than using the "batched" transaction, she runs a loop to call both transactions separately.

```solidity
function testZach__StealUsingRefund() public {
    vm.deal(address(alligator), 10 ether);

    address[] memory authority1 = new address[](2);
    authority1[0] = address(this);
    authority1[1] = address(Utils.alice);

    address[][] memory authorities1 = new address[][](1);
    authorities1[0] = authority1;

    address[] memory authority2 = new address[](2);
    authority2[0] = address(Utils.bob);
    authority2[1] = address(Utils.alice);

    address[][] memory authorities2 = new address[][](1);
    authorities2[0] = authority2;

    address[][][] memory authorities = new address[][][](2);
    authorities[0] = authorities1;
    authorities[1] = authorities2;

    Rules[] memory baseRulesBatch = new Rules[](2);
    baseRulesBatch[0] = baseRules;
    baseRulesBatch[1] = baseRules;

    alligator.subDelegateAll(Utils.alice, baseRules);
    alligator.create(Utils.bob, baseRules, true); // selfProxy

    vm.prank(Utils.bob);
    alligator.subDelegateAll(Utils.alice, baseRules);

    uint balanceBefore = Utils.alice.balance;
    uint gasBefore = gasleft();

    vm.startPrank(Utils.alice, Utils.alice);
    for (uint i = 0; i < 2; i++) {
        alligator.castRefundableVotesWithReasonBatched(baseRulesBatch, authorities[i], 1, 1, "");
    }

    uint gasAfter = gasleft();

    // Adjust Alice balance as if she paid for gas
    uint gasUsed = gasBefore - gasAfter;
    uint gasCost = gasUsed * tx.gasprice;
    uint balanceAfter = Utils.alice.balance - gasCost;
    uint profit = balanceAfter - balanceBefore;

    console.log("Gas Money Spent: ", (gasBefore - gasAfter) * tx.gasprice);
    console.log("Gas Money Refunded: ", Utils.alice.balance - balanceBefore);
    console.log("Profit (in gwei): ", profit);
}
```
This test can be dropped into `AlligatorV2.t.sol` and run with `forge test -vvv --match testZach__StealUsingRefund --gas-price 200`.

Simulating using a separate test written to run on live Nouns code, it appears the "profit" is ~3mm gwei for the first vote (but this is offset by the ~4mm gwei needed to kick off the exploit transaction). After the first vote, an additional profit of ~5mm gwei per vote is earned.

In a realistic future situation where a user has 20 Nouns delegated, there are 5 proposals live, gas is at the max value of 200 gwei, and ETH is worth $5k apiece, running this would result in a profit of:

`(5mm * (20 Nouns * 5 proposals) - 4mm) / 10^9 * $5k USD per ETH = ~$2500 USD`

## Recommendation

Remove gas refunding from the protocol and have refunds flow directly from Nouns.

If there is a reason to keep refunding in the protocol, two options exist to avoid this attack:

1) Check `require(msg.sender == tx.origin)` to stop contracts from collecting refunds. Users with multisigs or smart contract wallets could delegating voting to an EOA to collect refunds.

2) Send refunds to `tx.origin` instead of `msg.sender`, and track the last time a given `tx.origin` was refunded, not allowing more than 1 refund to a given address in the same block.

### Review

Since refunds have been removed from the protocol (see the fix to H-01), this is no longer an issue with Alligator.

## [L-01] Check for array length equality in subDelegateAllBatched

In `subDelegateAllBatched()`, the user submits two arrays: `targets` and `subDelegateRules`. We then create a delegation to each target for the corresponding set of rules.

There is no check that these arrays are equal in length. As a result, if `targets > subDelegateRules`, the final targets will be set with no rules (and therefore no permissions).

It would be helpful to verify the equality of these two arrays to avoid this situation.

## Recommendation

```diff
function subDelegateAllBatched(address[] calldata targets, Rules[] calldata subDelegateRules) external {
+   if (targets.length != subDelegateRules.length) revert MismatchedArrays();
    for (uint256 i; i < targets.length; ) {
        subDelegations[msg.sender][targets[i]] = subDelegateRules[i];

        unchecked {
            ++i;
        }
    }
    emit SubDelegations(msg.sender, targets, subDelegateRules);
}
```

### Review

Fixed as suggested in both `AlligatorV2.sol` and `Alligator.sol` in PR #14.

## [L-02] User may unexpectedly perform refund transaction without getting refund

_[Note: This is an issue with the fix to [H-01], not with the original code in the provided commit.]_

In `NounsDAOLogicV2.sol`, refunds are only provided if the voter actually has votes. Otherwise, the refund is silently skipped.
```solidity
function castRefundableVoteInternal(
    uint256 proposalId,
    uint8 support,
    string memory reason
) internal {
    uint256 startGas = gasleft();
    uint96 votes = castVoteInternal(msg.sender, proposalId, support);
    emit VoteCast(msg.sender, proposalId, support, votes, reason);
    if (votes > 0) {
        _refundGas(startGas);
    }
}
```
This makes sense in the case of Nouns, as the user will not be surprised that they do not have votes.

However, in Alligator, a user far down the authority chain may not realize that their "upstream" votes have undelegated. When this user votes, the transaction will run as expected, it will not revert, but no refund will be provided.

This is counter to the intuition a user would have about calling a function called `castRefundableVotesWithReasonBatched()` and observing the Alligator code.

## Recommendation

If we want to protect users from this possibility, implement the following check at the beginning of the function:
```solidity
if (nouns.getPriorVotes(proxy, nouns.proposalCreationBlock(proposalId)) == 0) revert NoVotes;
```
If we want to minimize gas costs and consider this check unnecessary, document the behavior clearly so that users know to confirm they still have votes before calling `castRefundableVotesWithReasonBatched()`, knowing that they will be charged the usual gas fee if this is not the case.

### Review

Protocol chose not to add this check to avoid the gas overhead on other users. They added the following note to the comments to warn users: `Note: The gas used will not be refunded for authority chains resulting in 0 votes cast.`

## [G-01] Cache array lengths before loops

To save gas, it is recommended to cache the length value before beginning a for loop (rather than recalculating it on each iteration).

This is performed in `validate()` but is not in `castVotesWithReasonBatched()`, `subDelegateAllBatched()`, or `subDelegateBatched()`.

Note that in `castVotesWithReasonBatched()`, the cached value can also be used as the length when creating the new `proxies` array.

## Recommendation

```diff
+   uint authorityLength = authorities.length;
+   for (uint256 i; i < authorityLength; ) {
-   for (uint256 i; i < authorities.length; ) {
        ...
    }
```
Similar adjustments can be made to the other functions.

### Review

Fixed as suggested in both `AlligatorV2.sol` and `Alligator.sol` in PR #14.

## [G-02] Slight gas savings by rearranging validate() function

At the end of the `validate()` function, we check if `from == sender` and return successfully if that's the case. Otherwise, we revert:

```solidity
if (from == sender) {
    return;
}

revert NotDelegated(from, sender, permissions);
```

It is slightly more gas efficient if we check for the inverse condition and revert in that case, and assume the successful return otherwise.

## Proof of Concept

Here is a simple test that calls `validate()` internally:
```solidity
function testZach__ValidateGasSavings() public {
    address[] memory authority = new address[](2);
    authority[0] = address(Utils.alice);
    authority[1] = address(this);

    vm.prank(Utils.alice);
    alligator.subDelegate(Utils.alice, baseRules, address(this), baseRules);

    alligator.castVote(baseRules, authority, 1, 1);
}
```
If you edit the function and run it both ways, you'll see the following:
```
CURRENT VERSION
[PASS] testZach__ValidateGasSavings() (gas: 504664)
Test result: ok. 1 passed; 0 failed; finished in 1.97ms

REVISED VERSION
[PASS] testZach__ValidateGasSavings() (gas: 504654)
Test result: ok. 1 passed; 0 failed; finished in 1.99ms
```

## Recommendation

```diff
-if (from == sender) {
-   return;
-}
+if (from != sender) revert NotDelegated(from, sender, permissions);

-revert NotDelegated(from, sender, permissions);
```

### Review

Fixed as suggested in both `AlligatorV2.sol` and `Alligator.sol` in PR #14.
