<table>
    <tr>
        <td><img src="https://avatars.githubusercontent.com/u/91336227?s=280&v=4" width="250" height="250" /></td>
        <td>
            <h1>0xSplits Audit Report</h1>
            <h2>Splits V2</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: Feb 19 to 23, 2023</p>
        </td>
    </tr>
</table>

# About **0xSplits**

0xSplits is a set of modular smart contracts for safe and efficient onchain payments. Splits V2 is a new architecture that combines an ERC6909 compliant token warehouse, with simple, minimal Split Wallets.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Lead Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

The [0xSplits/splits-contracts-monorepo](https://github.com/0xSplits/splits-contracts-monorepo) repository was audited at commit [9dde20f6a537675bc9ca47acb276ea9ecb2dcc26](https://github.com/0xSplits/splits-contracts-monorepo/commit/9dde20f6a537675bc9ca47acb276ea9ecb2dcc26).

The following contracts were in scope:
- src/libraries/Cast.sol
- src/libraries/Clone.sol
- src/libraries/Math.sol
- src/libraries/SplitV2.sol
- src/splitters/SplitWalletV2.sol
- src/splitters/SplitFactoryV2.sol
- src/tokens/ERC6909.sol
- src/tokens/ERC6909X.sol
- src/utils/Nonces.sol
- src/utils/Ownable.sol
- src/utils/Pausable.sol
- src/utils/UnorderedNonces.sol
- src/utils/Wallet.sol
- src/utils/ERC1271.sol
- src/SplitsWarehouse.sol

After completion of the fixes, [PR #24 (Fixes)](https://github.com/0xSplits/splits-contracts-monorepo/pull/24) and [PR #25 (ERC1271)](https://github.com/0xSplits/splits-contracts-monorepo/pull/25) were reviewed. The final commit reviewed was [740abb43a8961379cbe53cd2fd28287f28a47556](https://github.com/0xSplits/splits-contracts-monorepo/commit/740abb43a8961379cbe53cd2fd28287f28a47556).

# Summary of Findings

| Identifier | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [H-01] | If any Splits Wallet sets up incentives on Warehouse, all funds can be stolen | High | ✓ |
| [H-02] | Split ownership can be spoofed using `execCalls()` | High | ✓ |
| [M-01] | Splits with too many recipients can lead to locked funds | Medium |  |
| [M-02] | Rounding issues could allow majority shareholders to steal funds | Medium |  |
| [L-01] | Allocation size is unbounded, which can cause overflow revert in `getDistributions()` | Low |  |
| [L-02] | Precise pull distributions can be DOS'd with front running attack | Low | ✓ |
| [L-03] | OwnershipTransferred event emits incorrect data when called via `execCalls()` | Low | ✓ |
| [G-01] | `distribute()` accounting to keep balance of 1 is incorrect | Gas | ✓ |

# Detailed Findings

## [H-01] If any Splits Wallet sets up incentives on Warehouse, all funds can be stolen

There are two forms of incentives that can be added for distributions. On the `SplitsWarehouse`, incentives are added to the WithdrawConfig, and on the `SplitsWalletV2`, incentives are baked into the Split struct.

In the event that a Splits Wallet sets up any incentives on the Warehouse (and has their withdrawal config set to unpaused, which is the default state), this can be used to drain all funds from a user.

This is the case because the `warehouse.withdraw()` function and the `wallet.depositToWarehouse()` functions are public and permissionless. This means any use can withdraw, claiming the incentive, and force the wallet to immediately redeposit the funds. After enough cycles, the attacker will have claimed almost all of the assets.

### Proof of Concept

The following test can be dropped into `SplitWalletV2.t.sol` to demonstrate the attack.

```solidity
function testZach_IncentiveDrain() public {
    // set up an initial split, note that the parameters (including incentives) don't matter
    SplitReceiver[] memory _receivers = new SplitReceiver[](2);
    _receivers[0] = SplitReceiver({ receiver: address(1), allocation: 100 });
    _receivers[1] = SplitReceiver({ receiver: address(2), allocation: 100 });
    uint16 _distributionIncentive = 0;
    bool _distributeByPush = true;
    SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);
    address token = address(usdc);
    wallet.initialize(split, ALICE.addr);

    // ensure that an incentive is set on the Warehouse (we set at 1%, but can be any value)
    vm.prank(address(wallet));
    SplitsWarehouse.WithdrawConfig memory _config = SplitsWarehouse.WithdrawConfig({
        incentive: 1e4,
        paused: false
    });
    warehouse.setWithdrawConfig(_config);

    // deal the split $1mm to start
    dealSplit(address(wallet), token, 0, 1_000_000e6);

    // begin the attack
    address attacker = makeAddr("attacker");
    vm.startPrank(attacker);

    address[] memory _tokens = new address[](1);
    _tokens[0] = token;
    uint[] memory _amounts = new uint[](1);
    uint amountInWallet;

    // perform 2000 cycles of withdrawing (for an incentive) and redepositing, earning 1% each time
    for (uint i; i < 2000; i++) {
        (, _amounts[0]) = wallet.getSplitBalance(token);
        warehouse.withdraw(address(wallet), _tokens, _amounts, attacker);
        (amountInWallet,) = wallet.getSplitBalance(token);
        wallet.depositToWarehouse(token, amountInWallet);
    }

    // confirm that 99.9999% of the funds have been stolen
    (splitBal, warehouseBal) = wallet.getSplitBalance(token);
    assertGt(IERC20(token).balanceOf(attacker), 999_999e6);
    assertEq(splitBal, 0);
    assertLt(warehouseBal, 1e6);
}
```

The test passes, showing that the attacker has stolen all but $1 of the initial $1mm.

### Recommendation

The `depositToWarehouse()` function should be permissioned and only accessible to non-owners via the `distribute()` function.

### Review

Fixed in [PR #24](https://github.com/0xSplits/splits-contracts-monorepo/pull/24) by splitting push and pull splits into their own unique implementations. As a result, there is no way to redeposit assets in push splits, and no way to withdraw assets in pull splits.

The only exception is if a pull split allows withdrawals directly from the Warehouse. In this case, an attacker could call `withdraw()` on the warehouse, sending funds to the Wallet and earning the incentive, and then call `depositToWarehouse()` on the Wallet, sending the funds back to the Warehouse.

This situation is Acknowledged by the Splits team. They will add warnings to the docs and UI to warn users that a PullSplit where (a) withdrawal incentives are set on the Warehouse and (b) withdrawals are not paused on the warehouse, will be vulnerable to being drained.


## [H-02] Split ownership can be spoofed using `execCalls()`

Because the `onlyOwner` modifier allows calls from `address(this)`, we are able to call `transferOwnership()` from the `execCalls()` function.

Notably, once an `execCalls()` transaction has been started and the modifier has been passed, it can continue to call any `onlyOwner` functions (including `transferOwnership()`) until the transaction completes.

In any situation where an interacting protocol relies on an ownership check for a Split (for example, checking that the Split is immutable), this can be spoofed by using `execCalls()` to:

1) Transfer ownership to the required address (including `address(0)` to prove immutability)
2) Making the external call that checks ownership
3) Transferring ownership back to yourself in order to regain control

For example, we can imagine the following contract that is designed to register splits that are immutable and provide it with at least half of their revenue, seeing the included checks as a guarantee that this revenue stream will materialize:

```solidity
function registerSplit(SplitV2Lib.Split memory _splitParams, SplitWalletV2 _split) external {
    // require that the split params give this contract at least half of allocations
    require(_splitParams.recipients[0] == address(this);
    require(_splitParams.allocations[0] >= _splitParams.totalAllocation / 2);

    // require that these split params are really on the split
    require(_split.splitHash() == _splitParams.getHash());

    // require that the split is immutable so these values are locked
    require(_split.owner() == address(0));

    // go ahead with registering the split as valid
    ...
}
```
In this case, we could use `execCalls()` to transfer ownership to `address(0)`, then call `registerSplit()`, and finally transfer ownership back to ourselves.

### Recommendation

There are multiple possible solutions, depending how likely you think it is that interacting protocols will check Split ownership:

1) Simply document for interacting protocols that Split ownership checks (including immutability checks) should not be trusted.

2) Don't allow `execCalls()` to call `transferOwnership()`. Note that this doesn't completely solve the problem because in situations like the example above where we could call `execCalls()` from a contract, have it call back to the contract, the contract transfers ownership, the contract passes the immutability checks, and the `execCalls()` calls `updateSplit()` to change the params.

3) Check that the caller is the owner of the split before each call, reverting if ownership has changed.

### Review

Fixed in [PR #24](https://github.com/0xSplits/splits-contracts-monorepo/pull/24) by checking ownership in each iteration. Note that this allows a non-owner to call `execCalls()` with an empty array, but this is a no-op and won't cause any harm.

## [M-01] Splits with too many recipients can lead to locked funds

When calling `distribute()` for a given Wallet, it is required to send assets to all recipients. In the event that a Split is initialized with too many recipients, the gas cost of such a transaction can get so high that it will not fit within the block gas limit. In such a case, all funds will be stuck (unless there is an owner set who can recover them via `execCalls()`).

While a split this large seems unlikely, some of the larger current Splits (like Protocol Guild) have upwards of 100 recipients, so it seems in the range of possibility that larger Splits could be used at some point (especially with liquid Splits, where use cases like distributing to owners of a ~10k NFT collection might be common).

Based on gas estimates, it appears that ~1100 recipients is the point where such a failure would occur.

### Proof of Concept

The following test can be dropped into `SplitWalletV2.t.sol` to demonstrate that over 30mm gas is used when a Split distributes to 1100 members. Note that when `_distributeByPush` is changed to `false`, the number increases, but only slightly.

```solidity
function testZach_distributeGas() public {
    uint lengthToTest = 1100;
    bool _distributeByPush = true;

    address[] memory _receivers = new address[](lengthToTest);
    uint[] memory _amounts = new uint[](lengthToTest);
    for (uint i; i < lengthToTest; i++) {
        _receivers[i] = address(uint160(i + 1));
        _amounts[i] = 100;
    }

    SplitV2Lib.Split memory split = SplitV2Lib.Split({
        recipients: _receivers,
        allocations: _amounts,
        totalAllocation: 100 * lengthToTest,
        distributionIncentive: 0,
        distributeByPush: _distributeByPush
    });
    address token = address(usdc);

    wallet.initialize(split, ALICE.addr);
    dealSplit(address(wallet), token, 1e18, 9);

    uint gasBefore = gasleft();
    wallet.distribute(split, token, ALICE.addr);
    uint gasAfter = gasleft();

    assertGt(gasBefore - gasleft(), 30_000_000);
}
```

### Note on Validations

There are multiple other "safety check" validations that are not included when Splits are validated. These include checking for an empty Split (which won't send any payments), checking for duplicate addresses, etc. However, all of these boil down to user error. The user is getting the reasonably expected behavior, even if we think this behavior is unwanted.

This issue is different, because the result the user gets is not what they would reasonable expect. For this reason, I am submitting this as an issue to be fixed, while leaving the others for the Splits team to handle on the front end.

### Recommendation

Because some tokens may cost more gas to transfer, it's worth having some buffer to be safe.

My recommendation would be to explicitly validate that Splits can only be created with fewer than ~250 recipients.

```diff
function validate(Split calldata _split) internal pure {
    uint256 numOfRecipients = _split.recipients.length;
+   if (numOfRecipients > 250) revert InvalidSplit_TooManyRecipients();
    if (_split.allocations.length != numOfRecipients) {
        revert InvalidSplit_LengthMismatch();
    }

    uint256 totalAllocation;
    for (uint256 i; i < numOfRecipients; ++i) {
        totalAllocation += _split.allocations[i];
    }

    if (totalAllocation != _split.totalAllocation) revert InvalidSplit_TotalAllocationMismatch();
}
```

### Review

Acknowledged. Warnings will be added to the UI and docs.

## [M-02] Rounding issues could allow majority shareholders to steal funds

When distributions are calculated (using either push or pull), the `_split.calculateAllocatedAmount()` function is used to determine the amount.

```solidity
allocatedAmount = _amount * _split.allocations[_index] / _split.totalAllocation;
```
In the situation where one user holds a majority position in a Split, and the decimals of the token being distributed are very low, it is possible that an amount could be distributed such that minority positions are rounded down to zero and all funds are sent to the majority position.

Of course, with most normal tokens, the values required are so small that this doesn't present a risk. However, when tokens with very low decimals (such as [Gemini's GUSD](https://etherscan.io/token/0x056Fd409E1d7A124BD7017459dFEa2F387b6d5Cd?a=0x5f65f7b609678448494De4C87521CdF6cEf1e932)) are combined with a low cost chain, the risk presents itself.

(Note that, while GUSD is a rarer token with wei valued at $0.01 USD, more common tokens like WBTC could face a similar risk, with wei valued at $50,000 / 10**8 = 1/20th of a cent.)

### Proof of Concept

The following lays out the worst case scenario. A Split is heavily skewed towards a single user and the token being distributed has only 2 decimals. In this case, any time that $9.99 USD is distributed, it results in $8.99 going to the majority shareholder, while the other dollar remains in the Split. If this is repeated, the majority shareholder ends up with all the funds.

```solidity
function testZach_distributeMajorityTheft() public {
    // set up a split with 101 receivers, a 90% majority and one hundred 0.1% minorities
    address[] memory _receivers = new address[](101);
    uint[] memory _amounts = new uint[](101);

    _receivers[0] = makeAddr("majority");
    _amounts[0] = 900;

    for (uint i = 1; i < 101; i++) {
        _receivers[i] = address(uint160(i));
        _amounts[i] = 1;
    }

    SplitV2Lib.Split memory split = SplitV2Lib.Split({
        recipients: _receivers,
        allocations: _amounts,
        totalAllocation: 1000,
        distributionIncentive: 0,
        distributeByPush: true
    });
    wallet.initialize(split, address(0));

    // start the split off with $1000 of GUSD (1000_00)
    GUSD gusd = new GUSD();
    deal(address(gusd), address(wallet), 1000 * 10 ** gusd.decimals());
    assertEq(gusd.balanceOf(address(wallet)), 1000_00);

    // distribute GUSD in chunks of $9.99, which will only send funds to the majority
    for (uint i; i < 111; i++) {
        wallet.distribute(split, address(gusd), 9_99, 0, address(0));
    }

    // most GUSD is with the majority shareholder; the rest is in the wallet; minority partners have none
    assertEq(gusd.balanceOf(_receivers[0]), 997_89);
    assertEq(gusd.balanceOf(address(wallet)), 2_11);
}
```

### Recommendation

Given the extreme requirements necessary for this to become a risk, I believe a warning in the docs and UI would be sufficient to address it.

### Review

Acknowledged. Warnings will be added to the UI and docs.

## [L-01] Allocation size is unbounded, which can cause overflow revert in `getDistributions()`

A new feature in Splits V2 is that, rather than allocations being required to total a given `totalAllocation` amount, the `totalAllocation` amount is inferred from the `allocations`.

The `allocations` for a given split are `uint256`s, and there is no upper bound imposed on their size.

As a result, although it is unlikely, it is perfectly reasonable for a user to use extremely high values for the allocations, as long as the proportions are correct. Creating the split with such allocations will succeed as long as the total remains under `type(uint256).max`.

However, when calculating the amounts to distribute in `getDistributions()`, we call `calculateAllocatedAmount()`:

```solidity
function calculateAllocatedAmount(
    Split calldata _split,
    uint256 _amount,
    uint256 _index
)
    internal
    pure
    returns (uint256 allocatedAmount)
{
    allocatedAmount = _amount * _split.allocations[_index] / _split.totalAllocation;
}
```
As we can see, the `amount` is first multiplied by the `allocation` before being divided by the total.

The result is that any combination of `amount * _split.allocations[index]` that is greater than `type(uint256).max` will overflow and revert, causing the distribution to fail.

### Proof of Concept

The following test can be run which sets an allocation to `type(uint200).max` and then tries to allocation `1e18` of a token:

```solidity
function test_GetDistributionOverflow() external {
    address[] memory recipients = new address[](1);
    recipients[0] = address(1);
    uint[] memory allocations = new uint[](1);
    allocations[0] = type(uint200).max;

    SplitV2Lib.Split memory split = SplitV2Lib.Split(recipients, allocations, allocations[0], 0, false);
    (uint256[] memory amounts, uint256 distributorReward) = SplitV2Lib.getDistributionsMem(split, 1e18);
}
```
The result is a revert due to overflow:
```
[FAIL. Reason: panic: arithmetic underflow or overflow (0x11)] test_GetDistributionOverflow() (gas: 1330)
```

### Recommendation

Allocations should be limited to a max size. This is probably best accomplished by making them a type other than `uint256`. For example, if their size is `uint160`, that will allow the largest possible allocation to succeed when being paired with a deposit of size `type(uint96).max`, which is commonly assumed to be a safe upper bound on the size of ownership in any reasonable token.

### Review

Acknowledged. Warnings will be added to the UI and docs.

## [L-02] Precise pull distributions can be DOS'd with front running attack

Funds can be distributed in four ways: pushed with a full balance, pushed with a precise balance, pulled with a full balance, and pulled with a precise balance. This issue concerns only the fourth option, when funds are intended to be sent to the Warehouse to be pulled by users at a later time.

This path is activated by calling the second `distribute()` function when `_split.distributeByPush == false`:

```solidity
function distribute(
    SplitV2Lib.Split calldata _split,
    address _token,
    uint256 _distributeAmount,
    uint256 _warehouseTransferAmount,
    address _distributor
)
    external
    pausable
{
    if (splitHash != _split.getHash()) revert InvalidSplit();

    if (_split.distributeByPush) {
        // snip
    } else {
        if (_warehouseTransferAmount != 0) depositToWarehouse(_token, _warehouseTransferAmount);
        pullDistribute({ _split: _split, _token: _token, _amount: _distributeAmount, _distributor: _distributor });
    }
}
```
As we can see, we first call `depositToWarehouse()` with a specific balance to ensure our balance in the warehouse is sufficiently capitalized to allow the transfers to take place.

Then we call `pullDistribute()`, which performs a batch transfer of assets to all receivers, as well as the distributor.

The assumption is that we can enter an amount `_warehouseTransferAmount` that holds two properties:
1) `_warehouseTransferAmount <= warehouse balance`
2) `_warehouseTransferAmount + split balance >= _distributeAmount`

However, there are two permissionless functions that allow any user to move assets for a wallet between the wallet itself and the Warehouse.

```solidity
function depositToWarehouse(address _token, uint256 _amount) public {
    if (_token == NATIVE_TOKEN) {
        SPLITS_WAREHOUSE.deposit{ value: _amount }({ owner: address(this), token: _token, amount: _amount });
    } else {
        try SPLITS_WAREHOUSE.deposit({ owner: address(this), token: _token, amount: _amount }) { }
        catch {
            IERC20(_token).approve({ spender: address(SPLITS_WAREHOUSE), amount: type(uint256).max });
            SPLITS_WAREHOUSE.deposit({ owner: address(this), token: _token, amount: _amount });
        }
    }
}

function withdrawFromWarehouse(address _token) public {
    SPLITS_WAREHOUSE.withdraw(address(this), _token);
}
```
This allows a malicious attacker to watch the mempool for distributions and move assets to or from the Warehouse, such that one of the two invariants above can always be broken (either by pre-depositing assets to the Warehouse so there isn't enough for the `depositToWarehouse()` call, or by withdrawing sufficiently from the Warehouse so that the deposit plus the current balance isn't enough for the `pullDistribute()` transfers).

### Recommendation

`depositToWarehouse()` and `withdrawFromWarehouse()` should be permissioned `onlyOwner` functions, where the logic is moved to an internal function so it can be accessed permissionlessly, but only through the `distribute()` function.

### Review

Fixed in [PR #24](https://github.com/0xSplits/splits-contracts-monorepo/pull/24) by splitting push and pull implementations of the SplitWallet. As a result, the pull implementation (which uses the precise value for `depositToWarehouse()`) does not have a `withdrawFromWarehouse()` function.

Note that it is still possible to perform this attack by calling `withdraw()` directly on the Warehouse, but this can easily be stopped by a Split owner by setting `withdrawConfig[split].paused = true`.

## [L-03] OwnershipTransferred event emits incorrect data when called via `execCalls()`

When `transferOwnership()` is called, it emits the `OwnershipTransferred` event, which includes the old and new owners:
```solidity
function transferOwnership(address _owner) public virtual onlyOwner {
    owner = _owner;
    emit OwnershipTransferred({ oldOwner: msg.sender, newOwner: _owner });
}
```

It is assumed that, because the function is guarded by the `onlyOwner` modifier, the old owner can be inferred from `msg.sender`.

However, if we look at the modifier, we can see that calls from `address(this)` pass the check as well:
```solidity
modifier onlyOwner() virtual {
    if (msg.sender != owner && msg.sender != address(this)) revert Unauthorized();
    _;
}
```
This allows ownership to be transferred via `execCalls()`, where the owner can make any function calls on behalf of the contract. In this case, the event will mistakenly emit the wallet's address as the old owner.

### Proof of Concept

The following test can be dropped into `Wallet.t.sol` to demonstrate:

```solidity
function test_execCalls_transferOwnershipWrongEventData() public {
    Wallet.Call memory call = Wallet.Call({
        to: address(wallet),
        value: 0,
        data: abi.encodeWithSelector(Ownable.transferOwnership.selector, BOB.addr)
    });

    Wallet.Call[] memory calls = new Wallet.Call[](1);
    calls[0] = call;

    vm.expectEmit();
    emit OwnershipTransferred(address(wallet), BOB.addr);
    vm.prank(wallet.owner());
    wallet.execCalls{ value: 0 }(calls);
}
```

### Recommendation

```diff
function transferOwnership(address _owner) public virtual onlyOwner {
+   address oldOwner = owner;
    owner = _owner;
-   emit OwnershipTransferred({ oldOwner: msg.sender, newOwner: _owner });
+   emit OwnershipTransferred({ oldOwner: oldOwner, newOwner: _owner });
}
```

### Review

Fixed as recommended in [PR #24](https://github.com/0xSplits/splits-contracts-monorepo/pull/24).

## [G-01] `distribute()` accounting to keep balance of 1 is incorrect

In the `distribute()` function, we attempt to distribute all funds in the wallet and warehouse, leaving a balance of 1 in both places to avoid the gas costs of "un-zeroing" the storage slot later.

- In the `distributeByPush` code path, this calculation is done properly for the warehouse, but missed for the wallet.
- In the `!distributeByPush` code path, this calculation is done properly for the wallet balance, but missed for the warehouse.

It is possible that in some cases, the missed half still remains with a non-zero balance because of rounding, but in many cases, the result will be that one of the balances is changed to zero, despite efforts to avoid this.

### Proof of Concept

This test can be added to SplitWalletV2.t.sol, which demonstrates a distribution adjusting the split balance down to 0. Note that, if `distributeByPush = false`, the same would happen with the warehouse.

```solidity
function testZach_distribute() public {
    SplitReceiver[] memory _receivers = new SplitReceiver[](2);
    _receivers[0] = SplitReceiver({ receiver: address(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4), allocation: 100 });
    _receivers[1] = SplitReceiver({ receiver: address(0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2), allocation: 100 });
    uint16 _distributionIncentive = 0;
    bool _distributeByPush = true;

    SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);
    address token = address(usdc);

    wallet.initialize(split, ALICE.addr);
    dealSplit(address(wallet), token, 10, 9);

    (uint splitBefore, uint warehouseBefore) = wallet.getSplitBalance(token);
    wallet.distribute(split, token, ALICE.addr);
    (uint splitAfter, uint warehouseAfter) = wallet.getSplitBalance(token);

    assertEq(splitBefore, 10);
    assertEq(warehouseBefore, 9);
    assertEq(splitAfter, 0);
    assertEq(warehouseAfter, 1);
}
```

### Recommendation

When calling the internal `pushDistribute()` or `pullDistribute()` functions, subtract 1 from the passed amount to ensure that 1 token remains in the balance:

```diff
pullDistribute({
    _split: _split,
    _token: _token,
-   _amount: warehouseBalance + splitBalance,
+   _amount: warehouseBalance + splitBalance - 1,
    _distributor: _distributor
});
```

### Review

Fixed as recommended in [PR #24](https://github.com/0xSplits/splits-contracts-monorepo/pull/24).
