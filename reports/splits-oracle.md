<table>
    <tr>
        <td><img src="https://avatars.githubusercontent.com/u/91336227?s=280&v=4" width="250" height="250" /></td>
        <td>
            <h1>0xSplits Audit Report</h1>
            <h2>Chainlink Oracle & L2 Deployments</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: Nov 27 to 29, 2023</p>
        </td>
    </tr>
</table>

# About **0xSplits**

0xSplits is a set of simple, modular smart contracts for safe and efficient onchain payments. The Chainlink oracle will be used to determine asset prices for use with their `Swapper` module, which allows users to incentivize others to swap their holdings into a single token for withdrawal.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Lead Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

[PR #5](https://github.com/0xSplits/splits-oracle/pull/5) of the [0xSplits/splits-oracle](https://github.com/0xSplits/splits-oracle) repository was audited.

The following contracts were in scope:
- factory/BaseChainlinkOracleFactory.sol
- factory/ChainlinkOracleFactory.sol
- factory/ChainlinkOracleL2Factory.sol
- oracle/ChainlinkOracleImpl.sol
- oracle/ChainlinkOracleL2Impl.sol
- libraries/BytesLib.sol
- libraries/ChainlinkPairDetails.sol
- libraries/ChainlinkPath.sol
- libraries/PairDetails.sol

Additionally, the `UniV3OracleFactory` and `UniV3OracleImpl` were checked for safety on Optimism, Base and Arbitrum.

After completion of the fixes, the [46baca33](https://github.com/0xSplits/splits-oracle/pull/5/commits/46baca33aae9dac8db734af3c704ef8b77fed3e1) commit was reviewed.

# Summary of Findings

| Identifier | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [H-01] | UniV3 Oracle unsafe on L2s in event of Sequencer downtime | High | ✓ |
| [M-01] | High decimal tokens will lead to loss of precision in oracle results | Medium | ✓ |
| [M-02] | Tokens with extreme price differences along the path could round price to zero | Medium | ✓ |
| [L-01] | Rearrange stale price check formula out of absurd paranoia | Low | ✓ |
| [I-01] | Extra bytes can be included in pairDetails | Informational | ✓ |

# Detailed Findings

## [H-01] UniV3 Oracle unsafe on L2s in event of Sequencer downtime

The UniV3 oracle uses the built in `consult()` function provided by Uniswap's Oracle Library to query the pool and determine the time weighted price. This takes in a `secondsAgo` and observes the price at `secondsAgo` and `block.timestamp`, returning the time weighted average between these two points.

In the event that we haven't had any observation since `secondsAgo`, we assume the latest observation still holds:
```solidity
    function getSurroundingObservations(
        Observation[65535] storage self,
        uint32 time,
        uint32 target,
        int24 tick,
        uint16 index,
        uint128 liquidity,
        uint16 cardinality
    ) private view returns (Observation memory beforeOrAt, Observation memory atOrAfter) {
        // optimistically set before to the newest observation
        beforeOrAt = self[index];

        // if the target is chronologically at or after the newest observation, we can early return
        if (lte(time, beforeOrAt.blockTimestamp, target)) {
            if (beforeOrAt.blockTimestamp == target) {
                // if newest observation equals target, we're in the same block, so we can ignore atOrAfter
                return (beforeOrAt, atOrAfter);
            } else {
                // otherwise, we need to transform
                return (beforeOrAt, transform(beforeOrAt, target, tick, liquidity));
            }
        }
        ...
}
```
In the event that an L2's sequencer goes down, the time weighted price when it comes back online will be the extrapolated previous price. This will create an opportunity to push through transactions at the old price before it is updated. Even when the new price is observed, it will be assumed by the sequencer that the previous price held up until the moment it came back online, which will result in a slow, time weighted adjustment back to the current price.

Note that, in the case of Arbitrum, there is the ability to force transactions through the delayed inbox. If other users are forcing transactions into the given pool, this could solve the problem, but if not it could also make the problem worse by allowing an attacker to force a transaction that abuses the outdated price while the sequencer is down, guaranteeing inclusion.

### Recommendation

Use the Chainlink oracle for all L2s.

### Review

0xSplits will prioritize the Chainlink oracle for all L2s. In the event that they need to deploy the Uniswap oracle, they have implemented the following changes:
- check the Chainlink Sequencer Feed to confirm the sequencer is up
- confirm that the sequencer has been back up for at least 1 hour
- for each queried pool, confirm that the sequencer has been up for at least the period the TWAP will be taken over

This ensures that, even in the event that the sequencer goes down and therefore propagates the old prices throughout the downtime, that downtime will be completely out of the TWAP by the time the oracle can be queried.

These changes can be seen in the following commits: [3a8a7a01](https://github.com/0xSplits/splits-oracle/pull/5/commits/3a8a7a010d454628532aa4db3887a9330423467c), [59124dbc](https://github.com/0xSplits/splits-oracle/pull/5/commits/59124dbc46222dfdee74a7115965cd0a61fc9874), [46baca33](https://github.com/0xSplits/splits-oracle/pull/5/commits/46baca33aae9dac8db734af3c704ef8b77fed3e1)

## [M-01] High decimal tokens will lead to loss of precision in oracle results

When the Chainlink Oracle has calculated a relative price between two assets, it results in a `price`, which is always represented in 18 decimals. This price is used to convert the passed `baseAmount` into a final result:
```solidity
function _convertPriceToQuoteAmount(uint256 price_, QuoteParams calldata quoteParams_)
    internal
    view
    returns (uint256 finalAmount)
{
    uint8 baseDecimals = quoteParams_.quotePair.base._decimals();
    uint8 quoteDecimals = quoteParams_.quotePair.quote._decimals();

    finalAmount = price_ * quoteParams_.baseAmount / 10 ** baseDecimals;
    if (18 > quoteDecimals) {
        finalAmount = finalAmount / (10 ** (18 - quoteDecimals));
    } else if (18 < quoteDecimals) {
        finalAmount = finalAmount * (10 ** (quoteDecimals - 18));
    }
}
```
In the case of high decimal tokens, this function performs a large division before multiplying the amount back up by `(10 ** (quoteDecimals - 18))`. In that division and subsequent multiplication, there is a loss of precision that can lead to incorrect oracle results.

### Proof of Concept

The following proof of concept pulls out the `_convertPriceToQuoteAmount()` function to display its behavior more clearly. We create two tokens with 24 decimals ([highest value I know of that exists in the wild](https://etherscan.io/address/0xaba8cac6866b83ae4eec97dd07ed254282f6ad8a)) and presume they have equal value (`price = 1e18`). We input `amount = 1e6 - 1` for `tokenA`, which should return an equal number of `tokenB`, but instead returns `0`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { Test, console2 } from "forge-std/Test.sol";
import { ERC20 } from "solmate/tokens/ERC20.sol";
import {QuotePair, QuoteParams} from "splits-utils/LibQuotes.sol";
import {TokenUtils} from "splits-utils/TokenUtils.sol";

contract MockERC20 is ERC20 {
    constructor(uint8 decimals_) ERC20("Token", "TKN", decimals_) {}
}

contract HighDecimalsTest is Test {
    using TokenUtils for address;

    function _convertPriceToQuoteAmount(uint256 price_, QuoteParams memory quoteParams_)
        internal
        view
        returns (uint256 finalAmount)
    {
        uint8 baseDecimals = quoteParams_.quotePair.base._decimals();
        uint8 quoteDecimals = quoteParams_.quotePair.quote._decimals();

        finalAmount = price_ * quoteParams_.baseAmount / 10 ** baseDecimals;
        if (18 > quoteDecimals) {
            finalAmount = finalAmount / (10 ** (18 - quoteDecimals));
        } else if (18 < quoteDecimals) {
            finalAmount = finalAmount * (10 ** (quoteDecimals - 18));
        }
    }


    function testZach_getQuoteAmtsHighDecimals() public {
        // deploy two high decimal ERC20s
        MockERC20 tokenA = new MockERC20(24);
        MockERC20 tokenB = new MockERC20(24);

        // let's assume these two tokens have equal value
        // oracle always returns 1e18 prices, so:
        uint price = 1e18;

        // if we try to convert tokenA to tokenB,
        // division by baseDecimals will round us down
        // for small amounts, this will round down to 0
        uint128 amount = 1e6 - 1;
        QuotePair memory quotePair = QuotePair({base: address(tokenA), quote: address(tokenB)});
        QuoteParams memory quoteParams = QuoteParams({quotePair: quotePair, baseAmount: amount, data: ""});

        assertEq(_convertPriceToQuoteAmount(price, quoteParams), 0);
    }
}
```

### Recommendation

Change the order of operations in the relevant function so that multiplication comes before division:
```diff
function _convertPriceToQuoteAmount(uint256 price_, QuoteParams memory quoteParams_)
    internal
    view
    returns (uint256 finalAmount)
{
    uint8 baseDecimals = quoteParams_.quotePair.base._decimals();
    uint8 quoteDecimals = quoteParams_.quotePair.quote._decimals();

-   finalAmount = price_ * quoteParams_.baseAmount / 10 ** baseDecimals;
+   finalAmount = price_ * quoteParams_.baseAmount;
    if (18 > quoteDecimals) {
        finalAmount = finalAmount / (10 ** (18 - quoteDecimals));
    } else if (18 < quoteDecimals) {
        finalAmount = finalAmount * (10 ** (quoteDecimals - 18));
    }
+   finalAmount = finalAmount  / 10 ** baseDecimals;
}
```

### Review

[Fixed as recommended.](https://github.com/0xSplits/splits-oracle/commit/082662d17a75cec02fe6b0e43c6f4a69360fc99d)

## [M-02] Tokens with extreme price differences along the path could round price to zero

In the unlikely event that the price ratio between two tokens is more than `1e18:1`, the oracle will round the price down zero.

While the largest price ratio I can currently find is `BTC/SHIB` (which can be calculated using [SHIB/ETH](https://etherscan.io/address/0x8dD1CD88F43aF196ae478e91b9F5E4Ac69A97C61#readContract) and [ETH/BTC](https://etherscan.io/address/0xdeb288F737066589598e9214E782fa5A8eD689e8#readContract) to be approximately `1e11:1`), that puts us close enough to the range that this is something we should be prepared for.

Based on the use for this oracle with swappers, a `0` price would allow the bot executing the swap to steal all of a user's tokens for free.

Note that this `0` price could occur as an intermediate step along a longer path, and the `0` value would carry through to the final price, leading to the theft of tokens with closer values as well.

### Recommendation

While rounding is inevitable with such a large price discrepancy and 18 decimals of precision, it is worth including an explicit check that `price != 0` to ensure that tokens cannot be stolen.

```diff
function _getQuoteAmount(QuoteParams calldata quoteParams_) internal view returns (uint256) {
    ...
    if (pd.inverted) price = WAD.divWadDown(price);
+   if (price == 0) revert ZeroPrice();
    return _convertPriceToQuoteAmount(price, quoteParams_);
}
```

### Review

[Fixed as recommended.](https://github.com/0xSplits/splits-oracle/commit/71d6368d62f8ee28043861fc656d16d726261dc8)

## [L-01] Rearrange stale price check formula out of absurd paranoia

In `_getFeedAnswer()`, we check if the Chainlink oracle has returned a stale price:
```solidity
if (updatedAt < block.timestamp - feed_.staleAfter) {
    revert StalePrice(feed_.feed, updatedAt);
}
```
`feed_.staleAfter` is a `uint24`, so for any chain that uses standard Unix timestamps, it should be impossible for `block.timestamp - feed_.staleAfter` to underflow (because the current Unix time is greater than `type(uint24).max`).

However, out of an abundance of paranoia, it is worth rearranging the formula to accomplish the same thing without risk of reverting.

### Recommendation

```diff
- if (updatedAt < block.timestamp - feed_.staleAfter) {
+ if (updatedAt + feed_.staleAfter < block.timestamp) {
      revert StalePrice(feed_.feed, updatedAt);
  }
```

### Review

[Fixed as recommended.](https://github.com/0xSplits/splits-oracle/commit/aeae0e2d4241d3279f2db5294d7a619b393a818c)

## [I-01] Extra bytes can be included in pairDetails

When `$_pairDetails` are set, we store a bytestring (which represents a packed version of an array of Feeds) and an `inverted` boolean flag.

Before storing these values, we use `path.getFeeds()` to decode the bytestring into an array of Feeds and validate that the parameters passed are valid (ie that decimals equals the decimals on the feed and that `staleAfter` > 1 hour).

When these values are accessed, we also use the `path.getFeeds()` function to retrieve the feeds for oracle price calculations.

If we look at the implementation of `getFeeds()`, we can see that it first gets the number of feeds in the path, and then iterates over each of these feeds, calling `getFeed()` to decode and return it:
```solidity
/// @notice get feeds from a path (packed encoded bytes)
function getFeeds(bytes memory path) internal pure returns (ChainlinkOracleImpl.Feed[] memory feeds) {
    uint256 length = len(path);
    feeds = new ChainlinkOracleImpl.Feed[](length);
    for (uint256 i; i < length;) {
        feeds[i] = getFeed(path, i);
        unchecked {
            ++i;
        }
    }
}
```
```solidity
/// @notice get the number of feeds in the path
function len(bytes memory path) internal pure returns (uint256) {
    return path.len(PATH_UNIT_SIZE);
}
```
```solidity
function len(bytes memory _bytes, uint256 _size) internal pure returns (uint256) {
    return _bytes.length / _size;
}
```
If the length of the bytearray passed is not evenly divisible by 25, the extra bytes will be ignored by `getFeeds()`. This will skip validation, store the bytes in storage, and also skip returning them to be used when the oracle is called.

I do not see any harm in these extra bytes existing, but in the event that extra interactions are implemented at a later date or there is a risk I'm not seeing, it would be more precise and safer to require that bytestrings passed do not contain extra bytes.

### Recommendation

```diff
/// @notice get the number of feeds in the path
function len(bytes memory path) internal pure returns (uint256) {
+   if (path.length % 25 != 0) revert ExtraBytesInPath();
    return path.len(PATH_UNIT_SIZE);
}
```

### Review

[Fixed by performing recommended check directly in BytesLib.](https://github.com/0xSplits/splits-oracle/commit/aaff90ef0727918ba3e26069ba84ad88d85a8fec)
