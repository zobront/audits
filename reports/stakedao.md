<table>
    <tr><th></th><th></th></tr>
    <tr>
        <td><img src="https://styles.redditmedia.com/t5_45q11m/styles/communityIcon_iqrykrjom8p61.png" width="250" height="250" /></td>
        <td>
            <h1>StakeDAO Audit Report</h1>
            <h2>Votemarket</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: May 22 to May 26, 2023</p>
        </td>
    </tr>
</table>

# About **StakeDAO's Votemarket**

Stake DAO is a non-custodial platform where you can do more with your money. The Votemarket product is a platform for users to create and participate in bounties for voting on Curve's CRV allocation across gauges.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

The live contract at [0x0000000895cB182E6f983eb4D8b4E0Aa0B31Ae4c](https://etherscan.io/address/0x0000000895cB182E6f983eb4D8b4E0Aa0B31Ae4c) on Ethereum mainnet was audited.

The following contracts were in scope:
- Platform.sol


# Summary of Findings

| ID     | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| M-01 | Bounty manager can set `maxRewardPerVote` to 1 after votes are locked, stealing free votes | Medium |  |
| M-02 | `createBounty()` doesn't confirm that a `rewardToken` exists, which can be used to steal deterministic tokens | Medium |  |
| M-03 | Upgrades are put into effect immediately during first period | Medium |  |
| M-04 | Users cannot claim bounty in final week of their lock | Medium |  |
| M-05 | Race condition if bounty is extended in final period | Medium |  |
| L-01 | Blacklisted addresses will count towards total slope if they vote before rollover | Low |  |
| L-02 | Owner can steal funds from any user by abusing `setRecipientFor()` or `platformFee` | Low |  |
| L-03 | Manager can be set to address(0), which prevents bounty from being closed | Low |  |
| L-04 | `platformFee` can be set above 1e18, which would disable all claims | Low |  |
| G-01 | Can pack structs to use fewer storage slots | Gas |  |
| G-02 | `claimAllFor()` recipient check can be moved outside of the loop to save gas | Gas |  |
| G-03 | Calling `createBounty()` with invalid gauge will revert before returning 0 | Gas |  |

# Detailed Findings

## [M-01] Bounty manager can set `maxRewardPerVote` to 1 after votes are locked, stealing free votes

When the amount to pay for a `claim` is calculated, we use the minimum value of `bias * rewardPerVote` and `bias * maxRewardPerVote`.
```solidity
// Compute the reward amount based on
// Reward / Total Votes.
amount = _bias.mulWad(rewardPerVote[_bountyId]);

// Compute the reward amount based on
// the max price to pay.
uint256 _amountWithMaxPrice = _bias.mulWad(bounty.maxRewardPerVote);

// Distribute the _min between the amount based on votes, and price.
amount = FixedPointMathLib.min(amount, _amountWithMaxPrice);
```

Since `maxRewardPerVote` is a value that managers can edit at any time, this allows them to effectively reduce the bounty payouts to ~0 after votes have already been locked.

### Proof of Concept

1) A manager starts a new bribe for their gauge with 2 periods, a large total bounty, and a large `maxRewardPerVote`.
2) Users lock in their votes on Curve, which can't be changed for 10 days.
3) The day before the first period begins, the manager calls `increaseBountyDuration()` with `_newMaxPricePerVote = 1`.
4) When users claim, they will be paid only `bias * 1`, which is effectively 0.
5) After the two periods, the manager calls `closeBounty()` to be refunded almost the full amount.

### Recommendation

`maxRewardPerVote` should only be allowed to be increased midstream, similar to `numberOfPeriods` and `totalRewardAmount`.

This could be done by changing the argument to `_increasedMaxRewardPerVote` and adding it to the existing value, or simply by comparing the new and old value and requiring that `new >= old`.

### Review

TK

## [M-02] `createBounty()` doesn't confirm that a `rewardToken` exists, which can be used to steal deterministic tokens

When a new bounty is created with the `createBounty()` method, we use the solady `SafeTransferLib` to transfer the token into the contract:
```solidity
SafeTransferLib.safeTransferFrom(rewardToken, msg.sender, address(this), totalRewardAmount);
```
Digging into this function, we can see that, in the event that there is no return data, the function will always pass:
```solidity
function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
    /// @solidity memory-safe-assembly
    assembly {
        let m := mload(0x40) // Cache the free memory pointer.

        // Store the function selector of `transferFrom(address,address,uint256)`.
        mstore(0x00, 0x23b872dd)
        mstore(0x20, from) // Store the `from` argument.
        mstore(0x40, to) // Store the `to` argument.
        mstore(0x60, amount) // Store the `amount` argument.

        if iszero(
            and( // The arguments of `and` are evaluated from right to left.
                // Set success to whether the call reverted, if not we check it either
                // returned exactly 1 (can't just be non-zero data), or had no return data.
                or(eq(mload(0x00), 1), iszero(returndatasize())),
                call(gas(), token, 0, 0x1c, 0x64, 0x00, 0x20)
            )
        ) {
            // Store the function selector of `TransferFromFailed()`.
            mstore(0x00, 0x7939f424)
            // Revert with (offset, size).
            revert(0x1c, 0x04)
        }

        mstore(0x60, 0) // Restore the zero slot to zero.
        mstore(0x40, m) // Restore the free memory pointer.
    }
}
```
This means that a user can pass a non-contract address to this function and it will not revert, allowing them to set up a "bounty" with a non-existant reward token.

While this may not seem harmful, there are many token addresses that are deterministic. For example, we can predict the address of the next Curve LP token to be created, or the next token to be minted by the Optimism Bridge.

- In the event these contracts use CREATE, it can be calculated as: `address = keccak256(rlp([sender_address,sender_nonce]))[12:]`
- In the evenet these contracts use CREATE2, it can be calculated as: `address = keccak256(0xff + sender_address + salt + keccak256(initialisation_code))[12:]`

With knowledge of these addresses, we can create bounties using tokens that have not yet been deployed. The `safeTransferFrom` will not do anything, but will not revert, and the result will be a bounty with a large `totalRewardAmount` that isn't actually held in the contract.

In the event that any future user deposits this token into the contract to create a valid bounty, the malicious user can call `closeBounty()` to steal the funds.

### Recommendation

Add an explicit check before calling `safeTransferFrom` that the `rewardToken` is a contract and not an EOA.

```solidity
uint size;
assembly {
    size := extcodesize(rewardToken)
}
return size > 0;
```

### Review

TK

## [M-03] Upgrades are put into effect immediately during first period

When upgrades are made by a bounty manager by calling the `increaseBountyDuration()` function, they are stored in the `upgradeBountyQueue` mapping. The intention is that, when the next period is started, all upgrades will be put into effect and cleared out of the queue.

This is accomplished through the `_upgradeBountyPeriod()` function, which is called each time a bounty is claimed:
```solidity
function _updateBountyPeriod(uint256 bountyId) internal returns (uint256) {
    Period storage _activePeriod = activePeriod[bountyId];

    uint256 currentPeriod = getCurrentPeriod();

    if (_activePeriod.id == 0 && currentPeriod == _activePeriod.timestamp) {
        // Check if there is an upgrade in queue and update the bounty.
        _checkForUpgrade(bountyId);

        // Initialize reward per token.
        // Only for the first period, and if not already initialized.
        _updateRewardPerToken(bountyId, currentPeriod);
    }

    // Increase Period
    if (block.timestamp >= _activePeriod.timestamp + _WEEK) {
        // Checkpoint gauge to have up to date gauge weight.
        gaugeController.checkpoint_gauge(bounties[bountyId].gauge);

        // Check if there is an upgrade in queue and update the bounty.
        _checkForUpgrade(bountyId);

        // Roll to next period.
        _rollOverToNextPeriod(bountyId, currentPeriod);

        return currentPeriod;
    }

    return _activePeriod.timestamp;
}
```
As you can see `_checkForUpgrade(bountyId)` is called in both `if` clauses. The first `if` clause is intended to happen when the first period begins, while the second `if` clause occurs when each subsequent period is rolled over.

However, if we look at the logic for the first `if` clause, we can see that it will be called for EACH claim in the full period. This means that, if a bounty manager calls `increaseBountyDuration()` to update the bounty during the first period, the upgrade will be put into effect immediately (when the next `_claim()` is made), rather than at the start of the next period.

This would lead to different users within the same period being paid differently for the same bounty.

### Proof of Concept

Here is a test that can be dropped into your `Platform.t.sol` file to verify that upgrades during the first period will be put into effect right away, rather than waiting for the next period to roll over:

```solidity
function testZach__UpgradesInFirstPeriodAreImmediate() public {
    // Create Bounty throught the platform contract.
    uint256 id = _createCustomBounty();

    // Retrieve the Bounty with the Id.
    Platform.Bounty memory oldBounty = platform.getBounty(id);
    gaugeController.checkpoint_gauge(gauge);

    // Need to skip 2 week since the first period start one week after the bounty creation.
    skip(WEEK);
    gaugeController.checkpoint_gauge(gauge);

    // Claim the reward with a random account just to trigger roll over.
    vm.prank(address(0xBABA));
    platform.claim(id);

    rewardToken.mint(user, amount);
    rewardToken.approve(address(platform), amount);
    // Increase the number of periods.

    platform.increaseBountyDuration(id, 2, amount, 3e18);
    platform.updateBountyPeriod(id);

    Platform.Bounty memory bounty = platform.getBounty(id);
    assertEq(bounty.numberOfPeriods, 4);
}
```

### Recommendation

Restrict the first `if` clause to only be triggered once, by tightening the requirements of the `if` statement. For example:

```diff
- if (_activePeriod.id == 0 && currentPeriod == _activePeriod.timestamp) {
+ if (_activePeriod.id == 0 && currentPeriod == _activePeriod.timestamp && rewardPerVote[bountyId] == 0) {
    // Check if there is an upgrade in queue and update the bounty.
    _checkForUpgrade(bountyId);

    // Initialize reward per token.
    // Only for the first period, and if not already initialized.
    _updateRewardPerToken(bountyId, currentPeriod);
  }
```

If this change is made, we can then remove the check for `rewardPerVote[bountyId] == 0` from `_updateRewardPerToken()`.

### Review

TK

## [M-04] Users cannot claim bounty in final week of their lock

The `bias` used to determine how many votes a user is contributing to a given gauge is calculated as follows:
```solidity
function _getAddrBias(uint256 userSlope, uint256 endLockTime, uint256 currentPeriod)
    internal
    pure
    returns (uint256)
{
    if (currentPeriod + _WEEK >= endLockTime) return 0;
    return userSlope * (endLockTime - currentPeriod);
}
```
The check to short circuit and return `0` is too restrictive, and also results in returning `0` for the final (valid) week of a stake.

We can understand this intuitively by seeing that if `currentPeriod + _WEEK == endLockTime`, then we are currently in the week before the `endLockTime`.

During a given week, we are paid for the vote that happened at `currentPeriod` (the previous end of week). In this case, that vote was not the vote in which our lock expired, but the week before, when our vote was still valid.

### Proof of Concept

The following tests are standalone and can be copied into any Foundry test file. They demonstrate that, while the bias should be increasing by `604_800` per week, instead it remains at `0` for the first week, and then jumps to `604_800 * 2` the second week.

```solidity
    uint256 private constant _WEEK = 1 weeks;

    function _getAddrBias(uint256 userSlope, uint256 endLockTime, uint256 currentPeriod)
        internal
        pure
        returns (uint256)
    {
        if (currentPeriod + _WEEK >= endLockTime) return 0;
        return userSlope * (endLockTime - currentPeriod);
    }

    function getCurrentPeriod() public view returns (uint256) {
        return (block.timestamp / _WEEK) * _WEEK;
    }

    function testZach__AddrBiasFinalWeek() public {
        uint256 userSlope = 1; // should be 604_800 per week
        uint256 currentPeriod = getCurrentPeriod();
        console.log("Bias If Ends Current Period + 0: ", _getAddrBias(userSlope, currentPeriod, currentPeriod));
        console.log("Bias If Ends Current Period + 1: ", _getAddrBias(userSlope, currentPeriod + 1 weeks, currentPeriod));
        console.log("Bias If Ends Current Period + 2: ", _getAddrBias(userSlope, currentPeriod + 2 weeks, currentPeriod));
        console.log("Bias If Ends Current Period + 3: ", _getAddrBias(userSlope, currentPeriod + 3 weeks, currentPeriod));
    }
```

```
Logs:
  Bias If Ends Current Period + 0:  0
  Bias If Ends Current Period + 1:  0
  Bias If Ends Current Period + 2:  1209600
  Bias If Ends Current Period + 3:  1814400
```

### Recommendation

```diff
function _getAddrBias(uint256 userSlope, uint256 endLockTime, uint256 currentPeriod)
    internal
    pure
    returns (uint256)
{
-   if (currentPeriod + _WEEK >= endLockTime) return 0;
+   if (currentPeriod >= endLockTime) return 0;
    return userSlope * (endLockTime - currentPeriod);
}
```

### Review

TK

## [M-05] Race condition if bounty is extended in final period

When a manager calls `increaseBountyDuration()` to queue up a change in their bounty's parameters, there is a check that the bounty is still active:
```solidity
if (getPeriodsLeft(_bountyId) < 1) revert NO_PERIODS_LEFT();
```
This check reverts if the bounty is past the `endTimestamp`, but succeeds otherwise, because `getPeriodsLeft` is inclusive (ie it returns 1 in the final period).

In the event that an upgrade that extends a bounty is queued up during the final period, there is a race condition whether the bounty may be closed or extended, depending which function is called first after the period is ended.

If `closeBounty()` is called first, it simply checks that `getCurrentPeriod() >= bounty.endTimestamp` (which it will be, because `bounty` hasn't been updated yet). It then closes out the bounty and refunds any remaining funds.

If `updateBountyPeriod()` or `claim()` are called first, they will enter the `if` block that is triggered when we enter a new period:
```solidity
        if (block.timestamp >= _activePeriod.timestamp + _WEEK) {
            // Checkpoint gauge to have up to date gauge weight.
            gaugeController.checkpoint_gauge(bounties[bountyId].gauge);

            // Check if there is an upgrade in queue and update the bounty.
            _checkForUpgrade(bountyId);

            // Roll to next period.
            _rollOverToNextPeriod(bountyId, currentPeriod);

            return currentPeriod;
        }
```
In this block, `_checkForUpgrade()` is called, which will set the `bounties[bountyId]` values to those from the `upgradedBountyQueue`. This will have the effect of extending the bounty.

This race condition gives a manager power to manipulate payouts, because they can queue up a bounty extension with a large additional payout, and wait until the votes are cast to decide whether to extend (and have the payment be claimable) or close the bounty (and take a refund of all additional fees).

### Recommendation

The `closeBounty()` function should first call `_checkForUpgrade()` in order to pull any pending upgrades off the queue.

Only once this update is complete, should it check `if (getCurrentPeriod() >= bounty.endTimestamp || isKilled) ...` in order to determine if the bounty can be closed.

Alternatively, the `increaseBountyDuration()` function could be limited to only be allowed when `periodsLeft >= 2`, so no updates are permitted to happen in the final period.

### Review

TK

## [L-01] Blacklisted addresses will count towards total slope if they vote before rollover

When we roll over to a new period, we calculate the `rewardPerVote` by taking the `rewardPerPeriod` and dividing by the total bias (votes) for the gauge.

```solidity
uint256 gaugeBias = _getAdjustedBias(bounty.gauge, bounty.blacklist, currentPeriod);
rewardPerVote[bountyId] = rewardPerPeriod.mulDiv(_BASE_UNIT, gaugeBias);
```
In order to ensure these calculations are accurate, blacklisted addresses are not included in the the total bias calculation. Instead, they are manually removed one by one to get an adjusted bias:

```solidity
gaugeBias = gaugeController.points_weight(gauge, period).bias;

for (uint256 i = 0; i < length;) {
    // Get the user slope.
    userSlope = gaugeController.vote_user_slopes(_addressesBlacklisted[i], gauge);
    _lastVote = gaugeController.last_user_vote(_addressesBlacklisted[i], gauge);
    if (period > _lastVote) {
        _bias = _getAddrBias(userSlope.slope, userSlope.end, period);
        gaugeBias -= _bias;
    }
    // Increment i.
    unchecked {
        ++i;
    }
}
```
As we can see, there is a check in here that the subtraction only happens if `period > lastVote`. In other words, if the address has voted in the given period, their slope will count toward the total, even though they are on the blacklist.

As a result, in the case that a blacklisted address updates their vote immediately after a new period starts, their vote will be counted in the total `gaugeBias` when it shouldn't be.

### Recommendation

Due to the limitations of the Curve contract, I don't see another way this could be accomplished without adding a lot of complexity and storage costs.

I think the current solution is the best option, but documenting it as a minor miscalculation so users are aware.

### Review

TK

## [L-02] Owner can steal funds from any user by abusing `setRecipientFor()` or `platformFee`

The owner has the ability to steal all bounty rewards from users. This can be accomplished in either of two ways:

1) The owner has access to a function called `setRecipientFor()`, which allows them to set the recipient for any address.

```solidity
function setRecipientFor(address _for, address _recipient) external onlyOwner {
    recipient[_for] = _recipient;

    emit RecipientSet(_for, _recipient);
}
```
If this value is set to a malicious address, it can be quickly followed up with a call to `claimFor()`, which will send the user's bounty funds to the `recipient` address that was set.

2) There is no limit to how high `platformFee` can be set. If it's set to `1e18`, all proceeds of any claimed rewards will be captured as fees and nothing will be sent to the user.

### Recommendation

These appear to be intentional design decisions, so the purpose of this issue is mainly to document the trust assumption for users.

If you prefer to remove this trust assumption, this can be accomplished by hardcoding a `MAX_PLATFORM_FEE` and removing the `setRecipientFor()` function.

### Review

TK

## [L-03] Manager can be set to address(0), which prevents bounty from being closed

When a bounty is completed, the `closeBounty()` function is called to send the funds back to the manager. `closeBounty()` uses the manager's address as a proxy for whether the bounty has already been closed. It checks for this value at the start of the function, and deletes it at the end of the function to mark it as closed:
```solidity
function closeBounty(uint256 bountyId) external nonReentrant {
    Bounty storage bounty = bounties[bountyId];
    if (bounty.manager == address(0)) revert ALREADY_CLOSED();

    ...

    delete bounties[bountyId].manager;
    emit BountyClosed(bountyId, leftOver);
}
```
If the manager's address were set to `address(0)`, this would stop the function from being called.

This isn't possible from the `createBounty()` function, as it contains the following check:
```solidity
if (rewardToken == address(0) || manager == address(0)) revert ZERO_ADDRESS();
```

However, the `updateManager()` function does not have such a check:
```solidity
function updateManager(uint256 bountyId, address newManager) external onlyManager(bountyId) {
    emit ManagerUpdated(bountyId, bounties[bountyId].manager = newManager);
}
```
In the case that a manager updates the manager to `address(0)` (say, with the idea that this is showing the immutability of their bounty), they would lock themselves out from claiming refunds.

### Recommendation

Add a check to `updateManager()` to ensure that the `newManager` address is not `address(0)`:

```diff
function updateManager(uint256 bountyId, address newManager) external onlyManager(bountyId) {
+   if (newManager == address(0)) revert ZERO_ADDRESS();
    emit ManagerUpdated(bountyId, bounties[bountyId].manager = newManager);
}
```

### Review

TK

## [L-04] `platformFee` can be set above 1e18, which would disable all claims

The owner can set the platform fee at any time using this function:
```solidity
function setPlatformFee(uint256 _platformFee) external onlyOwner {
    fee = _platformFee;

    emit FeeUpdated(_platformFee);
}
```
There are no checks on this value. However, it is crucial that this value remain below `1e18` or the contract will no longer work, because in the `_claim()` function, when the `feeAmount` is calculated, we perform this calculation:
```solidity
if (fee != 0) {
    feeAmount = amount.mulWad(fee);
    amount -= feeAmount;
    feeAccrued[bounty.rewardToken] += feeAmount;
}
```
In the case that `fee > 1e18`, then `amount -= feeAmount` will underflow and the function will fail.

### Recommendation

Add a check to `setPlatformFee` to ensure the value set is below `1e18` (or some other hardcoded `MAX_FEE` you determine).

### Review

TK

## [G-01] Can pack structs to use fewer storage slots

Structs pack multiple values into a single storage slot if there are consecutive values that total to less than 32 bytes.

Each of the structs used (`Bounty`, `Upgrade`, and `Period`) have opportunity to be more tightly packed in two ways:

1) Certain values that will never have very high values could use smaller uints.

2) The order of values could be reorganized to put values that might be packed next to one another.

### Recommendation

As an example, the following arrangement would use 3 slots plus blacklist for Bounty, 1 slot for Upgrade, and 1 slot for Period.

The current implementation uses 6 slots plus blacklist for Bounty, 4 slots for Upgrade, and 3 slots for Period.

Since SSTOREs are some of the most expensive gas operations, this would lead to substantial gas savings when these values are being set.

```solidity
struct Bounty {
    // Address of the target gauge. -------------------------------
    address gauge; //                                              |
    // Number of periods. //                                       |
    uint8 numberOfPeriods; //                                      |
    // Timestamp where the bounty become unclaimable //            |
    uint40 endTimestamp; // ---------------------------------------

    // Manager. ---------------------------------------------------
    address manager; //                                            |
    // Max Price per vote. //                                      |
    uint96 maxRewardPerVote; // -----------------------------------

    // Total Reward Added. ----------------------------------------
    uint96 totalRewardAmount; //                                   |
    // Address of the ERC20 used for rewards. //                   |
    address rewardToken; // ----------------------------------------

    // Blacklisted addresses.
    address[] blacklist;
}

struct Upgrade {
    // Number of periods after increase. ---------------------------
    uint8 numberOfPeriods; //                                       |
    // Total reward amount after increase. //                       |
    uint96 totalRewardAmount;  //                                   |
    // New max reward per vote after increase.  //                  |
    uint96 maxRewardPerVote;  //                                    |
    // New end timestamp after increase.  //                        |
    uint40 endTimestamp; // ----------------------------------------
}

/// @notice Period struct.
struct Period {
    // Period id. --------------------------------------------------
    // Eg: 0 is the first period, 1 is the second period, etc. //   |
    uint8 id; //                                                    |
    // Timestamp of the period start. //                            |
    uint40 timestamp;  //                                           |
    // Reward amount distributed during the period. //              |
    uint128 rewardPerPeriod; // ------------------------------------
}
```

### Review

TK

## [G-02] `claimAllFor()` recipient check can be moved outside of the loop to save gas

The `claimAllFor()` function loops over a list of bounties and calls `_claim()` on each of them:
```solidity
function claimAllFor(address _user, uint256[] calldata ids) external {
    address _recipient = recipient[_user];
    uint256 length = ids.length;

    for (uint256 i = 0; i < length;) {
        uint256 id = ids[i];
        _claim(_user, _recipient != address(0) ? _recipient : _user, id);
        unchecked {
            ++i;
        }
    }
}
```
While the `_recipient` value is cached before the loop, we then proceed to check whether it equals `address(0)` on each iteration of the loop.

Instead, we could check it once before the loop, and set it to the correct value, which could then be used in each iteration.

### Recommendation

```diff
function claimAllFor(address _user, uint256[] calldata ids) external {
    address _recipient = recipient[_user];
+    if (_recipient == address(0)) _recipient = _user;
    uint256 length = ids.length;

    for (uint256 i = 0; i < length;) {
        uint256 id = ids[i];
-        _claim(_user, _recipient != address(0) ? _recipient : _user, id);
+        _claim(_user, _recipient : _user, id);
        unchecked {
            ++i;
        }
    }
}
```

### Review

TK

## [G-03] Calling `createBounty()` with invalid gauge will revert before returning 0

When `createBounty()` is called, the first check is to ensure that the `gauge` is valid on Curve's `gaugeController`:

```solidity
if (gaugeController.gauge_types(gauge) < 0) return newBountyId;
```
However, there is no way for this function call to return a value less than 0. We can see this by following the invariants in the Curve contract:
- `add_gauge` requires that the `gauge_type` argument is 0 or greater
- the value is added to the mapping as `gauge_type + 1`, so it must be 1 or greater
- when we call `gauge_types()`, it asserts that `gauge_type != 0`
- it then returns `gauge_type - 1`

As a result, we know that the only values that can be in the mapping are 0 (nothing stored) or 1 or greater (something stored).

In the former case, the `gauge_types()` function will revert. In the latter case, it'll pass the check. Therefore, there is no case in which the `if` statement will pass and return `0` in our function.

We can save a small amount of gas and have the contract behave more according to our expectations by removing this check.

### Recommendation

Rather than perform a check with the return value, we can simply call `gaugeController.gauge_types(gauge)`, which will revert in the case that the `gauge` is not set.

### Review

TK
