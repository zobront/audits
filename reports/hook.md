<table>
    <tr><th></th><th></th></tr>
    <tr>
        <td><img src="https://pbs.twimg.com/profile_images/1546537950703386625/DVGINeUm_400x400.jpg" width="250" height="250" /></td>
        <td>
            <h1>Hook Protocol Audit Report</h1>
            <h2>Hook Bid Pool</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: April 13 to 15, 2023</p>
        </td>
    </tr>
</table>

# About **Hook Protocol**

Hook is an NFT-native call options protocol, which allows anyone to create, buy, and sell options on ERC-721 assets.

The Hook Bid Pool feature is an off chain order book that allows option buyers to sign orders based on implied volatility, and sellers to execute option sales, with the protocol calculating the current Black Scholes option value.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

The [hookart/protocol](https://github.com/hookart/protocol) repository was audited at commit [0548fc7974983fc7406b8f51c81d388ab8a9b32a](https://github.com/hookart/protocol/commit/0548fc7974983fc7406b8f51c81d388ab8a9b32a).

The following contracts were in scope:
- src/HookBidPool.sol
- src/lib/PoolOrders.sol

Note: The Lyra Black Scholes implementation, the core Hook Protocol, the 0x validateProperty mechanism, and any other options instruments that intend to interact with HookBidPool were assumed to work as expected. The scope of this audit did not include diving deeply into these interactions, and focused on verifying HookBidPool in isolation.

After completion of the fixes, the [de64025fcf17d26d6f23775bc6d327148215758b](https://github.com/hookart/protocol/commit/de64025fcf17d26d6f23775bc6d327148215758b) commit was reviewed.

# Summary of Findings

| ID     | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [C-01] | Users with open bids can have wallets emptied using malicious instrument contract | Critical | ✓ |
| [H-01] | BPS_TO_DECIMAL conversion is wrong, leading users to overpay for options | High | ✓ |
| [H-02] | Incorrect adjustment for decimals in maxStrikePriceMultiple check | High | ✓ |
| [M-01] | Both oracle signers can be set to address(0), which allows arbitrary data to be fraudulently signed | Medium | ✓ |
| [M-02] | Centralization risk in off chain oracles (particularly priceOracleSigner) | Medium |   |
| [M-03] | maxStrikePriceMultiple will always fail when added in bips | Medium | ✓ |
| [M-04] | verifyingContract set incorrectly for EIP712 Domain Separator | Medium | ✓ |
| [L-01] | Setting role admins to self is not advised | Low | ✓ |
| [L-02] | ETH_SIGN'd messages should include len(message) and full message, not hash | Low | ✓ |
| [G-01] | Unnecessary check in `_performSellOptionOrderChecks()` | Gas | ✓ |
| [G-02] | getPoolOrderStructHash() can be turned into a pure function | Gas | ✓ |

# Detailed Findings

## [C-01] Users with open bids can have wallets emptied due to insufficient parameter validation

The `optionInstrumentationAddress` that is inputted by the seller as an argument to the `sellOption()` function is used for all checks within the function. The `optionMarketAddress` that is a part of the signed order is ignored, and the two are not validated against one another.

Because of this insufficient parameter validation, a malicious seller can create a fake instrument with the following properties:
- `getStrikePrice()` returns `1` (to maximize option value)
- `getExpiration()` returns the maximum time the user will allow (to maximize option value)
- `safeTransferFrom()` does not revert

Here is an example of the simplest version of such a contract:

```solidity
contract FakeInstrument {
    function getStrikePrice(uint id) public pure returns (uint) {
        return 1;
    }

    function getExpiration(uint id) public view returns (uint) {
        return block.timestamp + 79 days;
    }

    function safeTransferFrom(address from, address to, uint id) public {}
}
```

They can then call `sellOption()` with this fake instrument, and a value for `saleProceeds` that equals the lower of `underlying asset price - fee - 1` or `user's WETH balance - fee`.

Let's trace the flow of this attack through the contract:

1) In `_performSellOptionOrderChecks()`, we grab the strike price and expiration directly from the inputted contract. We can set the expiry to ensure we pass the checks ensuring that the expiration time is between `block.timestamp + order.minOptionDuration` and `block.timestamp + order.maxOptionDuration`.

2) The strike price and expiry are used in `_computeOptionAskAndBid()` to determine the price. By setting the strike price to 1, Black Scholes will return a value for the option of approximately the full price of the underlying asset. We also pass the `bid >= ask` check, because the bid will equal the underlying asset price, while we calculated the `saleProceed` value to ensure that, even with the fee added, it would stay below this threshold.

3) We also call `_validateOptionProperties()` with this address, but we can specify the return values from calls to the contract however we want to ensure we pass the `validateProperty` checks.

4) Finally, we call `safeTransferFrom()` on our phony address, which will transfer nothing to the buyer.

5) We then transfer `saleProceeds` from the maker to ourselves, and the fee to the protocol. Because we set `saleProceeds` intentionally to ensure that the resulting value would be less than or equal to the user's WETH balance, these transactions succeed and we steal the assets from the user.

### Proof of Concept

Here is a drop in test that can be added to your `HookBidPoolTest.t.sol` file to validate the finding.

In this case, I've assumed an underlying asset value of 50 ETH to take advantage of the user's account balance of 50 ETH, but other than that, used the original test setup and signing.
```solidity
function testZach__StealWithFakeInstrument() public {
    vm.warp(block.timestamp + 20 days);
    PoolOrders.Order memory order = _makeDefaultOrder();
    (Signatures.Signature memory signature, bytes32 orderHash) = _signOrder(order, bidderPkey);

    address fakeInstrument = address(new FakeInstrument());

    console.log("Victim Starting Balance: ", weth.balanceOf(address(bidder)));
    console.log("Attacker Starting Balance: ", weth.balanceOf(address(seller)));

    vm.prank(address(seller));
    bidPool.sellOption(
        order,
        signature,
        _makeAssetPriceClaim(50 ether),
        _makeOrderClaim(orderHash),
        47.5 ether,
        fakeInstrument,
        0
    );

    console.log("Victim Ending Balance: ", weth.balanceOf(address(bidder)));
    console.log("Attacker Ending Balance: ", weth.balanceOf(address(seller)));
}
```

Output:

```
Logs:
  Victim Starting Balance:  50000000000000000000
  Attacker Starting Balance:  0
  Victim Ending Balance:  125000000000000000
  Attacker Ending Balance:  47500000000000000000
```

### Recommendations

Verify that `order.optionMarketAddress == optionInstrumentAddress` for all calls to `sellOption()`.

### Review

Fixed in [PR #104](https://github.com/hookart/protocol/pull/104/) by removing the `optionInstrumentAddress` argument altogether and always using `order.optionMarketAddress`.

## [H-01] BPS_TO_DECIMAL conversion is wrong, leading users to dramatically overpay for options

The constant value used to convert bips to decimals is defined as:

```solidity
uint256 constant BPS_TO_DECIMAL = 10e14;
```
`10e14` is equivalent to `1e15`, which when multiplied by `10_000 bips` equals `1e19`, which is 10x higher than it should be.

The result is that the `decimalVol` and `rateDecimal` values calculated using this value are 10x inflated. When these values are passed into the Black Scholes algorithm, they result in incorrect bids, which automatically clear as approved by the user.

Because the volatility number increases the price of options more dramatically than the risk free rate decreases it, the result is (in most cases) a substantially increased option price.

### Proof of Concept

Using the default order values provided in your test suite, we can see the difference between the correct value and the calculated value by making the `_computeOptionAskAndBid()` function public and running the following test:

```solidity
function testZach__ConversionMakesBidTooLow() public {
        vm.warp(block.timestamp + 20 days);

        uint TIME_TO_EXPIRY = 2 weeks;
        uint VOL_DEC = 0.5e18;
        uint SPOT_DEC = 10e18;
        uint STRIKE_DEC = 12e18;
        int RATE_DEC = 0.05e18;

        (uint call,) = BlackScholes.optionPrices(
            BlackScholes.BlackScholesInputs({
                timeToExpirySec: TIME_TO_EXPIRY,
                volatilityDecimal: VOL_DEC,
                spotDecimal: SPOT_DEC,
                strikePriceDecimal: STRIKE_DEC,
                rateDecimal: RATE_DEC
            })
        );

        (, uint bid) = bidPool._computeOptionAskAndBid(
            _makeDefaultOrder(),
            _makeAssetPriceClaim(SPOT_DEC),
            block.timestamp + TIME_TO_EXPIRY,
            STRIKE_DEC,
            10 ether
        );

        console.log(call);
        console.log(bid);
    }
```

The result is a price over 200x higher for the same options:
```
Logs:
  13731454889016255
  3254808296693654060
```

### Recommendation

```diff
-uint256 constant BPS_TO_DECIMAL = 10e14;
+uint256 constant BPS_TO_DECIMAL = 1e14;
```

### Review

Fixed in [PR #104](https://github.com/hookart/protocol/pull/104/) by setting `BPS_TO_DECIMAL = UNIT / BPS`.

## [H-02] Incorrect adjustment for decimals in maxStrikePriceMultiple check

When comparing `order.maxStrikePriceMultiple` to the actual multiple by which the strike price exceeds the asset price, the calculation is performed as follows:

```solidity
require(
    order.maxStrikePriceMultiple == 0
        || (strikePrice - assetPrice.assetPriceInWei) * 10e18 / assetPrice.assetPriceInWei
            < order.maxStrikePriceMultiple,
    "option is too far out of the money"
);
```

As we can see, the difference in price is multiplied by `10e18` before being divided by the current price.

`10e18` is equivalent to `1e19`, which is 10x higher than the intended value.

The result is that the multiple representing the gap between the strike price and asset price will always be overrepresented by 10x, causing it to fail the comparison to the `maxStrikePriceMultiple`.

### Recommendation

```diff
require(
    order.maxStrikePriceMultiple == 0
-       || (strikePrice - assetPrice.assetPriceInWei) * 10e18 / assetPrice.assetPriceInWei
+       || (strikePrice - assetPrice.assetPriceInWei) * 1e18 / assetPrice.assetPriceInWei
            < order.maxStrikePriceMultiple,
    "option is too far out of the money"
);
```

### Review

Fixed in [PR #104](https://github.com/hookart/protocol/pull/104/) as suggested.

## [M-01] Both oracle signers can be set to address(0), which allows arbitrary data to be fraudulently signed

The `priceOracleSigner` is set using the following admin-only function:
```solidity
function setPriceOracleSigner(address _priceOracleSigner) external onlyRole(ORACLE_ROLE) {
    priceOracleSigner = _priceOracleSigner;
    emit PriceOracleSignerUpdated(_priceOracleSigner);
}
```
Similarly, the `orderValidityOracleSigner` is set with this function:
```solidity
function setOrderValidityOracleSigner(address _orderValidityOracleSigner) external onlyRole(ORACLE_ROLE) {
    orderValidityOracleSigner = _orderValidityOracleSigner;
    emit OrderValidityOracleSignerUpdated(_orderValidityOracleSigner);
}
```
There are no checks on what either of these values are set to.

While I'm not usually a fan of zero address checks (because in most cases, the zero address would be no worse than setting an arbitrary other un-owned address), in this case, it is important.

This is because, later, asset price claims are validated as follows:

```solidity
function _validateAssetPriceClaim(AssetPriceClaim calldata claim) internal view {
    bytes memory claimEncoded =
        abi.encode(claim.assetPriceInWei, claim.priceObservedTimestamp, claim.goodTilTimestamp);

    bytes32 claimHash = keccak256(claimEncoded);
    bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", claimHash));

    address signer = ecrecover(prefixedHash, claim.v, claim.r, claim.s);

    require(signer == priceOracleSigner, "Claim is not signed by the priceOracle");
    require(claim.goodTilTimestamp > block.timestamp, "Claim is expired");
}
```
And whether the validity oracle signed is validated as follows:
```solidity
function _validateOrderValidityOracleClaim(OrderValidityOracleClaim calldata claim, bytes32 orderHash)
    internal
    view
{
    bytes memory claimEncoded = abi.encode(orderHash, claim.goodTilTimestamp);

    bytes32 claimHash = keccak256(claimEncoded);
    bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", claimHash));

    address signer = ecrecover(prefixedHash, claim.v, claim.r, claim.s);

    require(signer == orderValidityOracleSigner, "Claim is not signed by the orderValidityOracle");
    require(claim.goodTilTimestamp > block.timestamp, "Claim is expired");
}
```
Both of these functions check whether the return value of `ecrecover` matches with the oracle's address. However, any malicious user is able to create a fraudulent signature which returns `address(0)` from ecrecover. See [this example](https://gist.github.com/axic/5b33912c6f61ae6fd96d6c4a47afde6d) for how this can be done.

In the case that `orderValidityOracleSigner` is set to `address(0)`, an attacker could execute orders that have been cancelled off-chain.

In the case that `priceOracleSigner` is set to `address(0)`, an attacker could drain the accounts of any user with open bids by submitting extremely high asset values for the assets they've made offers on, leading to arbitrarily high bid prices.

### Recommendation

Check when these oracles are being set to confirm that the new value is not `address(0)`.

Alternatively, you could verify in the `_validateAssetPriceClaim()` and `_validateOrderValidityOracleClaim()` functions that `signer != address(0)`. However, I would recommend the former solution, as we'd rather keep the gas used in common functions as low as possible.

### Review

Fixed in [PR #104](https://github.com/hookart/protocol/pull/104/) by checking that neither oracle's address is set to `address(0)`, either in the constructor or in the setter functions.

## [M-02] Centralization risk in off chain oracles (particularly priceOracleSigner)

The protocol uses two off chain oracles to (a) verify asset prices and (b) allow gasless cancellations.

Each of these off chain signers pose a centralization risk for the protocol:

- `priceOracleSigner`: This signer submits the asset prices used in the Black Scholes calculation for option value. If a malicious actor were to get control of this wallet, they could drain all the funds from every the wallet of every user with open bids by submitting high spot price values that would push the option value up.

- `orderValidityOracleSigner`: This signer submits confirmation that the buyer has not gaslessly cancelled their order, and it is therefore valid to execute. If a malicious actor were to get control of this wallet, they could execute cancelled transactions, forcing buyers to buy assets they did not intend to.

Both off chain signers have their risks, but the `orderValidityOracleSigner` seems to be accomplishing an important goal (gasless cancellations) and the downsides are limited: orders that have no yet expired can be executed within the originally defined bounds, based on the accurate asset price.

The `priceOracleSigner`, on the other hand, seems to create an undue risk for users.

### Recommendation

For `orderValidityOracleSigner`, consider whether the feature of gasless cancellations is worth the key compromise risk.

For `priceOracleSigner`, it is recommended to use a reputable, decentralized oracle such as Chainlink for such an important source of data. Unfortunately, [Chainlink's NFT Floor Price](https://docs.chain.link/data-feeds/nft-floor-price/addresses/) feeds are limited to only 10 NFTs at the moment, so I understand that this would pose a major trade off for the protocol.

### Review

Acknowledged.

## [M-03] maxStrikePriceMultiple will always fail when added in bips

`maxStrikePriceMultiple` is defined as how many bips out of the money an option can be filled at:

```solidity
/// @notice bips in the money or out of the money an option can be filled at. For example, 5000 == 50% out of the money max for a call option. 0 means no max
uint256 maxStrikePriceMultiple;
```
It is used in the following check:
```solidity
require(
    order.maxStrikePriceMultiple == 0
        || (strikePrice - assetPrice.assetPriceInWei) * 10e18 / assetPrice.assetPriceInWei
            < order.maxStrikePriceMultiple,
    "option is too far out of the money"
);
```
This equality assumes that `maxStrikePriceMultiple` is calculated in decimals.

Therefore, any value that is set in bips will be far too small, and will fail the check.

### Recommendation

Change `maxStrikePriceMultiple` to define the decimal value, instead of the bips value.

### Review

Fixed in [PR #104](https://github.com/hookart/protocol/pull/104/) by defining `maxStrikePriceMultiple` as a decimal value, rather than a bips value.

## [M-04] verifyingContract set incorrectly for EIP712 Domain Separator

When the EIP712 Domain Separator is calculated, we input the `hookAddress` and perform the following function:
```solidity
function setAddressForEipDomain(address hookAddress) internal {
    // Compute `EIP712_DOMAIN_SEPARATOR`
    {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        EIP712_DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(" "string name," "string version," "uint256 chainId," "address verifyingContract"
                    ")"
                ),
                keccak256("Hook"),
                keccak256("1.0.0"),
                chainId,
                hookAddress
            )
        );
    }
}
```
This correctly uses the name, version, chain id, and verifying contract to generator a domain separator to be used for all EIP 712 encoding.

However, if we look at `HookBidPool.sol` at where this function is being called, we see the following:

```solidity
constructor(..., address _protocol) {
    ...
    setAddressForEipDomain(_protocol);
    ...
}
```
```solidity
function setProtocol(address _protocol) external onlyRole(PROTOCOL_ROLE) {
    setAddressForEipDomain(_protocol);
    protocol = IHookProtocol(_protocol);
    emit ProtocolAddressSet(_protocol);
}
```
These two function use the Hook protocol address to create the domain. However, EIP712 advises that you use the verifying contract itself (in other words, `HookBidPool.sol` for this value).

There are two reasons for this:

1) If you implement signature checks elsewhere within the protocol, it could result in signature collision and potential replay attacks.

2) If you change the protocol address and update it using `setProtocol()`, all previously signed bids will become invalid.

### Recommendation

Set the address for EIP712 Domain Separator to `address(this)` in the constructor, and set the variable to `immutable` so that it cannot be changed in the future.

### Review

Fixed in [PR #104](https://github.com/hookart/protocol/pull/104/) by using `address(this)` in the constructor, setting the variable to immutable, and removing the domain separator update from the `setProtocol()` function.

## [L-01] Setting role admins to self is not advised

HookBidPool defines four roles: ORACLE_ROLE, PAUSER_ROLE, PROTOCOL_ROLE, and FEES_ROLE. Each of these is set  to the `_initialAdmin` in the constructor, with plans to transfer the roles to separate wallets:
```solidity
_grantRole(ORACLE_ROLE, _initialAdmin);
_setRoleAdmin(ORACLE_ROLE, ORACLE_ROLE);
_grantRole(PAUSER_ROLE, _initialAdmin);
_setRoleAdmin(PAUSER_ROLE, PAUSER_ROLE);
_grantRole(PROTOCOL_ROLE, _initialAdmin);
_setRoleAdmin(PROTOCOL_ROLE, PROTOCOL_ROLE);
_grantRole(FEES_ROLE, _initialAdmin);
_setRoleAdmin(FEES_ROLE, FEES_ROLE);
```
The code above grants each of these roles to `_initialAdmin`, and also sets the role's admin to self.

This pattern is not advised, and is only recommended to be used for one master admin role with special safety precautions taken. This is because the pattern can result in permanently losing access to functions gated to a specific role if that role is ever renounced or revoked.

Instead, it is recommended to use the `DEFAULT_ADMIN_ROLE` as the admin for for these different roles, and to grant this role to highly trusted addresses (ideally with some redundancy in case keys are lost).

### Recommendation

Start off by granting the `DEFAULT_ADMIN_ROLE` to the `_initialAdmin`:
```solidity
_grantRole(ORACLE_ROLE, _initialAdmin);
_grantRole(PAUSER_ROLE, _initialAdmin);
_grantRole(PROTOCOL_ROLE, _initialAdmin);
_grantRole(FEES_ROLE, _initialAdmin);
_grantRole(DEFAULT_ADMIN_ROLE, _initialAdmin);
```
Then you can proceed to grant the admin role to trusted multisigs or the DAO governance address for maximum safety.

### Review

Fixed in [PR #104](https://github.com/hookart/protocol/pull/104/) as suggested.

## [L-02] ETH_SIGN'd messages should include len(message) and full message, not hash

In both `_validateOrderValidityOracleClaim()` and `_validateAssetPriceClaim()`, we check the message that has been signed by the off-chain oracle by encoding the data as follows:

```solidity
bytes32 claimHash = keccak256(claimEncoded);
bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", claimHash));
```

This does not follow the format laid out in EIP 191, which specifies that the message following the prefix should be `len(message) ‖ message` and not `keccak(message`.

While it seems that the prefix is only being used for ease of testing, it is important not to mix and match signature standards. If you use the EIP 191 standard for signed messages, it is advised to follow it as written.

### Recommendation

Encode the data as follows to follow the EIP 191 standard:
```solidity
bytes32 claimLen = len(claimEncoded);
bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", claimLen, claimEncoded));
```

### Review

Fixed in [PR #105](https://github.com/hookart/protocol/pull/105/) by using OpenZeppelin's ECDSA library.

## [G-01] Unnecessary check in `_performSellOptionOrderChecks()`

`_performSellOptionOrderChecks()` performs the following two checks:

```solidity
require(expiry > block.timestamp, "Option is expired");
require(block.timestamp + order.minOptionDuration < expiry, "Option is too close to expiry");
```
Since `order.minOptionDuration` is unsigned, it is necessarily the case that `block.timestamp + order.minOptionDuration >= block.timestamp`.

Therefore, if the second check passes, it is necessarily true that the first check would have passed as well.

We can save some gas by removing the first check.

### Recommendations

```diff
-require(expiry > block.timestamp, "Option is expired");
 require(block.timestamp + order.minOptionDuration < expiry, "Option is too close to expiry");
```

### Review

Fixed in [PR #104](https://github.com/hookart/protocol/pull/104/) as suggested.

## [G-02] getPoolOrderStructHash() can be turned into a pure function

`getPoolOrderStructHash()` encodes and hashes an order to create the `structHash` for EIP 712 signing:
```solidity
function getPoolOrderStructHash(Order memory poolOrder) internal view returns (bytes32) {
    return keccak256(abi.encodePacked(_hashPt1(poolOrder), _hashPt2(poolOrder)));
}
```
Since `_ORDER_TYPEHASH` and `_PROPERTY_TYPEHASH` are constants, this function does not read from storage.

It can therefore be changed from `view` to `pure` to save on gas.

### Recommendation

```diff
-function getPoolOrderStructHash(Order memory poolOrder) internal view returns (bytes32) {
+function getPoolOrderStructHash(Order memory poolOrder) internal pure returns (bytes32) {
     return keccak256(abi.encodePacked(_hashPt1(poolOrder), _hashPt2(poolOrder)));
 }
```

### Review

Fixed in [PR #104](https://github.com/hookart/protocol/pull/104/) as suggested.
