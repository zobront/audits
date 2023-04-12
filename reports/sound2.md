<table>
    <tr><th></th><th></th></tr>
    <tr>
        <td><img src="../logos/sound.jpg" width="250" height="250" /></td>
        <td>
            <h1>Sound.xyz Audit Report</h1>
            <h2>Minter V2s</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: April 7 to 12, 2023</p>
        </td>
    </tr>
</table>

# About **Sound.xyz**

Sound is a platform for creating collaboration between musicians and fans. Users support artists they love directly, and become a part of the song's history: owning an early edition (NFT), making a public comment on the song, and accessing an exclusive community.

This security review focused on the V2s for each of the Minter contracts. These contracts are attached to Editions to allow artists to set prices, enforce quantity bounds, time bounds, merkle lists, signature verification, and other customizations for their mints.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

[PR #34](https://github.com/soundxyz/sound-protocol-private/pull/34) of the [soundxyz/sound-protocol-private](https://github.com/soundxyz/sound-protocol-private/) repository was audited.

The following contracts were in scope:
- modules/BaseMinterV2.sol
- modules/EditionMaxMinterV2.sol
- modules/FixedPriceSignatureMinterV2.sol
- modules/MerkleDropMinterV2.sol
- modules/RangeEditionMinterV2.sol
- modules/MinterAdapter.sol
- modules/utils/DelegateCashLib.sol


After completion of the fixes, the final version of TK was reviewed.

# Summary of Findings

| ID     | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [H-01] | [Anyone can frontrun fixed price signature mints to waste claim ticket]() | High |  |
| [M-01] | [Affiliate payment are skipped if incorrect or empty proof is submitted]() | Medium |  |
| [M-02] | [All fees accrue to minters, which can be forked to use platform without fees]() | Medium |  |
| [M-03] | [Potentially unsafe use of forceSafeTransferETH]() | Medium |  |
| [L-01] | [Admin can frontrun and rug affiliates]() | Low |  |
| [N-01] | [EditionMaxMinterV2 overrides totalPrice() with identical function]() | Non-Critical |  |
| [G-01] | [Time range check performed multiple times]() | Gas |  |

# Detailed Findings

## [H-01] Anyone can frontrun fixed price signature mints to waste claim ticket

When NFTs are minted using the `FixedPriceSignatureMinterV2.sol` contract, the user is able to input any quantity to mint. As long as this amount is less than the quantity that has been signed for, the transaction will succeed and the claim ticket will be used up.

The signed ticket includes the following details:
- Buyer
- Mint ID
- Claim Ticket
- Signed Quantity
- Affiliate

When `mintTo()` is called, these values are all filled in entirely from the arguments passed to the function, as we can see here:
```solidity
bytes32 digest = keccak256(
    abi.encodePacked(
        "\x19\x01",
        DOMAIN_SEPARATOR(),
        keccak256(abi.encode(MINT_TYPEHASH, to, mintId, claimTicket, signedQuantity, affiliate))
    )
);
```
This leaves us with two facts:

1) The signature used by Alice to claim her NFTs could equally have been used by Bob to send NFTs to Alice, because there is no reference to who the `msg.sender` is when checking the signature.

2) The signature used to claim `signedQuantity` NFTs could also have been used to claim any amount `x` (where 0 < `x` <= `signedQuantity`), because there is no reference to the quantity claimed in the signature.

As a result, any user who is claiming a large number of NFTs is vulnerable to being frontrun. Bob can watch the mempool for Alice's transaction, copy the signature, and replay his own version of the transaction, sending just 1 NFT to Alice instead of the full `signedQuantity`.

Once this action has been taken, Alice's ticket will be claimed, and she will be unable to claim the additional NFTs she was entitled to.

This attack does require Bob to pay for Alice's NFT, but it because especially harmful in free or low price NFT mints, where there are likely large quantities that will be minted by top users and the attack can be performed for only the gas cost.

### Recommendation

I will think more on this, but the best option I can see is to encode the claim ticket bitmap by individual NFT to be claimed rather than by user. Then, a user could pass an array of `claimTicket` indices in order to mark these specific indices as claimed, while retaining their other tickets as claimable.

Other approaches would require including the `msg.sender` in the signature, or forcing users to claim the full `signedQuantity`, but both of these seem overly restrictive.

### Review

TK


## [M-01] Affiliate payment are skipped if incorrect or empty proof is accidentally submitted

When an NFT is minted, the user has the option to submit an `affiliate` and an `affiliate proof`.

The `_mintTo()` function performs the following logic to send the affiliate fee:

```solidity
t.affiliated = isAffiliatedWithProof(edition, mintId, affiliate, affiliateProof);
unchecked {
    if (t.affiliated) {
        // Compute the affiliate fee.
        t.affiliateFee = (t.totalPrice * uint256(baseData.affiliateFeeBPS)) / uint256(BPS_DENOMINATOR);
        // Deduct the affiliate fee from the remaining payment.
        // Won't underflow as `affiliateFee <= remainingPayment`.
        t.remainingPayment -= t.affiliateFee;
        // Increment the affiliate fees accrued.
        affiliateFeesAccrued[affiliate] = SafeCastLib.toUint128(
            uint256(affiliateFeesAccrued[affiliate]) + t.affiliateFee
        );
    }
}
```
As we can see, if `t.affiliated` is false, the payout is simply skipped. To determine whether `t.affiliated` is true, it performs the following check:
```solidity
function isAffiliatedWithProof(
    address edition,
    uint128 mintId,
    address affiliate,
    bytes32[] calldata affiliateProof
) public view virtual override returns (bool) {
    bytes32 root = _getBaseData(edition, mintId).affiliateMerkleRoot;
    // If the root is empty, then use the default logic.
    if (root == bytes32(0)) {
        return affiliate != address(0);
    }
    // Otherwise, check if the affiliate is in the Merkle tree.
    // The check that that affiliate is not a zero address is to prevent libraries
    // that fill up partial Merkle trees with empty leafs from screwing things up.
    return
        affiliate != address(0) &&
        MerkleProofLib.verifyCalldata(affiliateProof, root, _keccak256EncodePacked(affiliate));
}
```
As we can see, if no `affiliate` is set, we return false. This is important because we don't want to send affiliate fees to the zero address.

However, in the event where an affiliate and a proof are submitted and they are incorrect, we also return false (checking the `MerkleProofLib.verifyCalldata()` function, we can see that this also returns false rather than reverting for incorrect proofs).

This is not the ideal behavior, and can lead to affiliate-sent mints occurring and affiliates missing their payouts, with no chance for the proof to be fixed.

This is especially important in the event when affiliate merkle proofs are first turned on by an edition. Most affiliates will be pushing users to the `mint()` function, which is implemented as follows:
```solidity
function mint(
    address edition,
    uint128 mintId,
    uint32 quantity,
    address affiliate
) public payable {
    mintTo(edition, mintId, msg.sender, quantity, affiliate, MerkleProofLib.emptyProof(), 0);
}
```
As we can see, an empty proof is submitted. Until affiliates have been given a chance to update their front ends to calculate merkle proofs and use the `mintTo()` function, these mints will automatically succeed but not pay the affiliate.

Affiliates would much prefer to have mints revert until they implement the feature, rather than cutting them out of the payout.

### Recommendation

If a user specifically inputs an `affiliate` address and a `proof`, it's clear their intention is to have the affiliate paid. If this proof is incorrect, the function should revert to let them try again, rather than moving forward without paying the affiliate.

I would recommend adjusting `isAffiliatedWithRoot()` to revert if an incorrect proof is submitted:
```diff
function isAffiliatedWithProof(
    address edition,
    uint128 mintId,
    address affiliate,
    bytes32[] calldata affiliateProof
) public view virtual override returns (bool) {
    bytes32 root = _getBaseData(edition, mintId).affiliateMerkleRoot;
    // If the root is empty, then use the default logic.
    if (root == bytes32(0)) {
        return affiliate != address(0);
    }
    // Otherwise, check if the affiliate is in the Merkle tree.
+   if (!MerkleProofLib.verifyCalldata(affiliateProof, root, _keccak256EncodePacked(affiliate))) revert InvalidMerkleRoot()

    // The check that that affiliate is not a zero address is to prevent libraries
    // that fill up partial Merkle trees with empty leafs from screwing things up.
    return affiliate != address(0)
}
```

### Review

TK

## [M-02] All fees accrue to minters, which can be forked to use platform without fees

All platform fees accrue on the minters, rather than the core `SoundEditionV1_2.sol` contract. These contracts allow the Sound team to set platform fees (both a percentage and a flat fee), and then withhold them from mint fees as follows:

```solidity
unchecked {
    t.platformFlatFee = uint256(quantity) * uint256(platformFlatFee);
    t.totalPrice = totalPrice(edition, mintId, to, quantity);
    t.requiredEtherValue = t.totalPrice + t.platformFlatFee;

    // Reverts if the payment is not enough.
    if (msg.value < t.requiredEtherValue) revert Underpaid(msg.value, t.requiredEtherValue);

    // Compute the platform fee.
    t.platformFee = (t.totalPrice * uint256(platformFeeBPS)) / uint256(BPS_DENOMINATOR) + t.platformFlatFee;
    // Increment the platform fees accrued.
    platformFeesAccrued = SafeCastLib.toUint128(uint256(platformFeesAccrued) + t.platformFee);
    // Deduct the platform fee.
    // Won't underflow as `platformFee <= requiredEtherValue`;
    t.remainingPayment = t.requiredEtherValue - t.platformFee;
}
```
However, the Sound front end is populated based on editions that are created using the factory.

Once an edition is created, minters can be added arbitrarily by the edition owner by adding minters as addresses to the `MINTER_ROLE` on the contract:
```solidity
function grantRoles(address user, uint256 roles) public payable virtual onlyOwner {
    _grantRoles(user, roles);
}

function _grantRoles(address user, uint256 roles) internal virtual {
    /// @solidity memory-safe-assembly
    assembly {
        // Compute the role slot.
        mstore(0x0c, _ROLE_SLOT_SEED)
        mstore(0x00, user)
        let roleSlot := keccak256(0x0c, 0x20)
        // Load the current value and `or` it with `roles`.
        roles := or(sload(roleSlot), roles)
        // Store the new value.
        sstore(roleSlot, roles)
        // Emit the {RolesUpdated} event.
        log3(0, 0, _ROLES_UPDATED_EVENT_SIGNATURE, shr(96, mload(0x0c)), roles)
    }
}
```
This allows an edition owner to create an edition with no minters (or a dummy minter with an extremely high price), fork the Sound minter contract, and attach the forked minter to their edition. They will then be able to use the Sound platform without paying any fees.

### Recommendation

Check the `_ROLES_UPDATED_EVENT_SIGNATURE` events from all editions to ensure they have only 1 minter and it is an official Sound minter in order to display them on the front end.

### Review

TK

## [M-03] Potentially unsafe use of forceSafeTransferETH

When a new NFT is minted with the `_mintTo()` function, we check that `msg.value >= t.requiredEtherValue` and then refund the excess at the end of the function using `forceSafeTransferETH()`:

```solidity
if (msg.value > t.requiredEtherValue) {
    SafeTransferLib.forceSafeTransferETH(msg.sender, msg.value - t.requiredEtherValue);
}
```
This function works by attempting to send the value to the address and, if it fails, creating a temporary contract with the balance and self destructing it to force the ETH to the address:
```solidity
function forceSafeTransferETH(address to, uint256 amount) internal {
    // Manually inlined because the compiler doesn't inline functions with branches.
    /// @solidity memory-safe-assembly
    assembly {
        // If insufficient balance, revert.
        if lt(selfbalance(), amount) {
            // Store the function selector of `ETHTransferFailed()`.
            mstore(0x00, 0xb12d13eb)
            // Revert with (offset, size).
            revert(0x1c, 0x04)
        }
        // Transfer the ETH and check if it succeeded or not.
        if iszero(call(_GAS_STIPEND_NO_GRIEF, to, amount, 0, 0, 0, 0)) {
            mstore(0x00, to) // Store the address in scratch space.
            mstore8(0x0b, 0x73) // Opcode `PUSH20`.
            mstore8(0x20, 0xff) // Opcode `SELFDESTRUCT`.
            // We can directly use `SELFDESTRUCT` in the contract creation.
            // Compatible with `SENDALL`: https://eips.ethereum.org/EIPS/eip-4758
            pop(create(amount, 0x0b, 0x16))
        }
    }
}
```

The issue is that, in the case of a mint, it could be harmful for the refunded ETH to be forced to `msg.sender`.

For example, let's consider a situation where a user uses the `Multicaller` contract at `0x000000000088228fCF7b8af41Faf3955bD0B3A41`. This contract would become the `msg.sender` for their mint and would receive the gas refund. Since it doesn't have a `receive()` function, it would ordinarily revert, but in this case would have the ETH forced into the contract balance. It would then become a race between the user and MEV bots to extract the ETH.

This is one example, but this same issue exists in any situation where a user might use an intermediate contract to pass along a call without the ability for this contract to receive their refund.

### Recommendation

While there are many cases where the use of `forceSafeTransferETH()` is helpful, in the case of refunds for overpaying for NFTs, it would be preferable for non-receiving contracts to revert to allow the user to determine a different call path (or send the correct `msg.value` to avoid there being a refund).

### Review

TK

## [L-01] Admin can frontrun and rug affiliates

The admin has the ability to set the affiliate fee and affiliate merkle root at any time, using the following functions:

```solidity
function setAffiliateFee(
    address edition,
    uint128 mintId,
    uint16 bps
) public virtual override onlyEditionOwnerOrAdmin(edition) {
    if (bps > MAX_AFFILIATE_FEE_BPS) revert InvalidAffiliateFeeBPS();
    _getBaseData(edition, mintId).affiliateFeeBPS = bps;
    emit AffiliateFeeSet(edition, mintId, bps);
}

function setAffiliateMerkleRoot(
    address edition,
    uint128 mintId,
    bytes32 root
) public virtual override onlyEditionOwnerOrAdmin(edition) {
    _getBaseData(edition, mintId).affiliateMerkleRoot = root;
    emit AffiliateMerkleRootSet(edition, mintId, root);
}
```
When new NFTs are minted, the `_mintTo()` function calculates the affiliate fee on the fly and adds this to the affiliate's pending payouts.

```solidity
t.affiliated = isAffiliatedWithProof(edition, mintId, affiliate, affiliateProof);
unchecked {
    if (t.affiliated) {
        // Compute the affiliate fee.
        t.affiliateFee = (t.totalPrice * uint256(baseData.affiliateFeeBPS)) / uint256(BPS_DENOMINATOR);
        // Deduct the affiliate fee from the remaining payment.
        // Won't underflow as `affiliateFee <= remainingPayment`.
        t.remainingPayment -= t.affiliateFee;
        // Increment the affiliate fees accrued.
        affiliateFeesAccrued[affiliate] = SafeCastLib.toUint128(
            uint256(affiliateFeesAccrued[affiliate]) + t.affiliateFee
        );
    }
}
```
This creates the possibility for an edition owner to frontrun large purchase transactions to either (a) reduce the affiliate fee to zero or (b) change the affiliate merkle root, which will cause the transaction to move forward as expected, but not give the affiliate their share of profits.

### Recommendation

It is recommended that affiliate fees be locked once a mint begins, so affiliates can refer buyers with confidence that the fee will be paid out as expected.

It is important for merkle roots to be set while a mint is in process (to battle spam), but the fix proposed in #35 will ensure that transactions meant to rug affiliates by changing this root will revert rather than move forward, which provides an added layer of certainty.

### Review

TK

## [N-01] EditionMaxMinterV2 overrides totalPrice() with identical function

In `BaseMinterV2.sol`, the `totalPrice()` function is implemented as follows:

```solidity
    function totalPrice(
        address edition,
        uint128 mintId,
        address, /* to */
        uint32 quantity
    ) public view virtual override returns (uint128) {
        unchecked {
            // Will not overflow, as `price` is 96 bits, and `quantity` is 32 bits. 96 + 32 = 128.
            return uint128(uint256(_getBaseData(edition, mintId).price) * uint256(quantity));
        }
    }
```

In most of the V2 inheriting contracts (`MerkleDropMinterV2.sol`, `FixedPriceSignatureMinterV2.sol`, `RangeEditionMinterV2.sol`), the `totalPrice()` function is not implemented, because they all use the same calculation.

`EditionMaxMinterV2.sol` similarly uses the same formula to calculate `totalPrice()`, but overrides the functions with an identical implementation, which doesn't impact behavior.

### Recommendation

Remove the `totalPrice()` function from `EditionMaxMinterV2.sol` to allow it to inherit automatically from `BaseMinterV2.sol`.

### Review

TK


## [G-01] Time range check performed multiple times

When `RangeEditionMinterV2.sol.setTimeRange()` is called, we pass the `startTime`, `cutoffTime`, and `endTime` to the function.

```solidity
function setTimeRange(
    address edition,
    uint128 mintId,
    uint32 startTime,
    uint32 cutoffTime,
    uint32 endTime
) public onlyEditionOwnerOrAdmin(edition) {
    _requireValidCombinedTimeRange(startTime, cutoffTime, endTime);
    // Set cutoffTime first, as its stored value gets validated later in the execution.
    EditionMintData storage data = _editionMintData[_baseDataSlot(_getBaseData(edition, mintId))];
    data.cutoffTime = cutoffTime;

    // This calls the overriden `setTimeRange`, which will check that
    // `startTime < cutoffTime < endTime`.
    RangeEditionMinterV2.setTimeRange(edition, mintId, startTime, endTime);

    emit CutoffTimeSet(edition, mintId, cutoffTime);
}
```
First, we perform the check to `_requireValidCombinedTimeRange()`, which ensures our times are in the correct order:
```solidity
function _requireValidCombinedTimeRange(
    uint32 startTime,
    uint32 cutoffTime,
    uint32 endTime
) internal pure {
    if (!(startTime < cutoffTime && cutoffTime < endTime)) revert InvalidTimeRange();
}
```
Then we call out to the other `setTimeRange()` function, which only takes the start and end times, but performs an identical check:
```solidity
function setTimeRange(
    address edition,
    uint128 mintId,
    uint32 startTime,
    uint32 endTime
) public override(BaseMinterV2, IMinterModuleV2) onlyEditionOwnerOrAdmin(edition) {
    EditionMintData storage data = _editionMintData[_baseDataSlot(_getBaseData(edition, mintId))];
    if (!(startTime < data.cutoffTime && data.cutoffTime < endTime)) revert InvalidTimeRange();

    BaseMinterV2.setTimeRange(edition, mintId, startTime, endTime);
}
```

Finally, we call to `BaseMinterV2.setTimeRange()`, which additionally checks that `startTime < endTime`:
```solidity
function setTimeRange(
    address edition,
    uint128 mintId,
    uint32 startTime,
    uint32 endTime
) public virtual onlyEditionOwnerOrAdmin(edition) {
    if (startTime >= endTime) revert InvalidTimeRange();

    BaseData storage baseData = _getBaseData(edition, mintId);
    baseData.startTime = startTime;
    baseData.endTime = endTime;
    emit TimeRangeSet(edition, mintId, startTime, endTime);
}
```
### Recommendations

These checks can be consolidated to save gas.

At the very least, we can remove the check from the `setTimeRange()` with 5 arguments, as it will always call to the version with 4 arguments that performs the same check.

Further, it may be optimal to refactor to an internal `_setTimeRange()` function on `BaseMinterV2.sol`, since we will be able to skip this check and the `onlyEditionOwnerOrAdmin` modifier..

### Review

TK
