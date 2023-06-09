<table>
    <tr><th></th><th></th></tr>
    <tr>
        <td><img src="https://pbs.twimg.com/profile_images/1605623310708248576/xjVA-iGp_400x400.png" width="250" height="250" /></td>
        <td>
            <h1>Sentiment Audit Report</h1>
            <h2>0x & Aura Controllers</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: May 11th to 12th, 2023</p>
        </td>
    </tr>
</table>

# About **Sentiment**

Sentiment is a liquidity protocol enabling on-chain, permissionless, undercollateralized borrowing. They accomplish this through the creation of a Sentiment "Account", a contract that holds all deposited and borrowed assets in order to maximize leverage (by hypothecating all assets), while allowing the borrowed assets to be deployed across the DeFi ecosystem.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

[PR #64](https://github.com/sentimentxyz/controller/pull/64) and [PR #59](https://github.com/sentimentxyz/controller/pull/59) of the [sentimentxyz/controller](https://github.com/sentimentxyz/controller/) repo were audited.

The following contracts were in scope:
- src/0x/TransformController.sol
- src/aura/RewardPoolController.sol

After completion of the fixes, the [TK](tk.com) commit was reviewed.

# Summary of Findings

| ID     | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [H-01] | AURA token will not be accounted for in `tokensIn` | High | ✓ |
| [M-01] | New 0x transformers are allowed by default, which could lead to unexpected problems | Medium |  |
| [M-02] | Many 0x transformations ignore outputToken, returning unaccounted for tokens to account and risking liquidations | Medium |  |
| [L-01] | `withdraw()` and `redeem()` do not send any reward tokens | Low | ✓ |
| [L-02] | If ETH is used as an input and output token to 0x, it will always revert | Low |  |

# Detailed Findings

## [H-01] AURA token will not be accounted for in `tokensIn`

When the controller sees a call to Aura's `getReward()` function, it uses the following logic to set `tokensOut` and `tokensIn`:
```solidity
function canCallGetReward(address target) internal view returns (bool, address[] memory, address[] memory) {
    uint256 rewardLength = IRewards(target).extraRewardsLength();
    address[] memory tokensIn = new address[](rewardLength + 1);
    for (uint256 i = 0; i < rewardLength; i++) {
        tokensIn[i] = IRewards(IRewards(target).extraRewards(i)).rewardToken();
    }
    tokensIn[rewardLength] = IRewards(target).rewardToken();
    return (true, tokensIn, new address[](0));
}
```
This sets the `tokensIn` to equal an array with all the `extraRewards` tokens, as well as the target contract's `rewardToken`.

However, if we examine the code itself, we will see that `getReward()` sends out all the tokens we accounted for (the `rewardToken` as well as all the `extraRewards`) and also makes the following call:
```solidity
IDeposit(operator).rewardClaimed(pid, _account, reward);
```
https://github.com/convex-eth/platform/blob/b93b7b77169777f3d508feffc646042709e40ef7/contracts/contracts/BaseRewardPool.sol#L263-L279

Following that logic, we find the following function in the `Booster.sol` contract:
```solidity
function rewardClaimed(uint256 _pid, address _address, uint256 _amount) external returns(bool){
    address rewardContract = poolInfo[_pid].crvRewards;
    require(msg.sender == rewardContract || msg.sender == lockRewards, "!auth");

    //mint reward tokens
    ITokenMinter(minter).mint(_address,_amount);

    return true;
}
```
https://github.com/convex-eth/platform/blob/b93b7b77169777f3d508feffc646042709e40ef7/contracts/contracts/Booster.sol#L458C12-L466

As we can see, this additional call mints the `AURA` token to the `receiver`.

This token is not accounted for in `tokensIn`, which means it will not contribute to an account's balance in Sentiment. As a result, the account could be unfairly liquidated due to the missing balance.

### Recommendation

Add the `AURA` token to the `tokensIn` array. If the deployment on Arbitrum matches Mainnet, it can be accessed as follows:
```solidity
IBooster(IRewards(target).operator()).minter();
```

### Review

Fixed in [commit 49db04366e255568f0cab1e6e083b9fff808b384](https://github.com/sentimentxyz/controller/pull/64/commits/49db04366e255568f0cab1e6e083b9fff808b384) as recommended.

## [M-01] New 0x transformers are allowed by default, which could lead to unexpected problems

When the controller checks `canCall()` for calls to the 0x contract, it begins by checking that `sig == 0x415565b0`.

If this check fails (ie if any other function is called), the call is not allowed. However, if it passes, all possible calls are allowed. There is no further validation.

The `transformERC20()` function being called takes in some assets, as well as transformer nonces (which are translated to addresses) and calldata to pass to these addresses. The 0x contract then executes these calls and returns the assets to the caller.

The 0x contract has its own logic to ensure that only valid 0x transformers can be called, so there is no risk of malicious addresses being passed. However, because each of these transformers performs a different function, and more transformers can be added at any time, there is a risk that a new transformer will be added that causes unexpected behavior.

As an example, one could imagine a transformer that allows a user to approve an Operator. This Operator could then make calls to 0x on their behalf. If this was possible, all of Sentiment could be drained with the following exploit:
- Take a flash loan and deposit a large amount of funds into Sentiment (> 20% of protocol's TVL).
- Borrow the maxmimum amount of funds against it and convert all funds into one token.
- Approve 0x to transfer this token on behalf of the Sentiment account.
- Call `transformERC20()` with the transformer that sets another Operator.
- After the `exec()` call, the account is still healthy, so it's permitted.
- From the Operator account, call `transformERC20()` with to pull funds from the Sentiment account, with another non-Sentiment account as the receiver.
- Since the call is not coming from Sentiment, there is no way to check account health after it is executed, and the pulled funds represent all of Sentiment's TVL.

While I do not think adding such a feature is likely, it is clear that allowing calls to a contract that implements arbitrary logic is very dangerous. The current architecture leaves the door open for 0x to make changes down the road that will be accepted automatically by the Sentiment protocol without being analyzed and approved by the Sentiment team.

### Recommendation

A safer approach may be to examine the transformers one by one, and specifically create an allowlist for which transformers are known to be safe.

This would default to new transformers not being allowed until approved by the Sentiment team, which seems like a more appropriate strategy when delegating to external logic.

(It would also have the added benefit of allowing more granular knowledge of `tokensIn`, as discussed in H-01.)

### Review

Acknowledged. The Sentiment team spoke to the 0x team, who confirmed that they do not currently support any form of smart contract signatures, and that signed messages are the only way that one user could trade on behalf of another user.

The Sentiment team plans to keep a careful eye on all 0x transformer deployments and other features (as well as keeping lines of communication open with the 0x team) in order to ensure that any changes in this response are caught and addressed.

## [H-02] Many 0x transformations ignore outputToken, returning unaccounted for tokens to account and risking liquidations

When we call `transformERC20()` on the 0x contract, the following inputs are included as arguments:
```solidity
function transformERC20(
    address inputToken,
    address outputToken,
    uint256 inputTokenAmount,
    uint256 minOutputTokenAmount,
    Transformation[] calldata transformations
) external payable returns (uint256 outputTokenAmount);
```
`TransformController.sol` assumes that `outputToken` will be the only token returned.

However, if we look at the implementation of the function on 0x, we see the following flow:
- all tokens are transferred into the `state.wallet` contract
- we execute all the transformations based on our specified parameters
- after the transformations, if the `state.wallet` has any of our output token, it is transferred back to us
- we ensure that our balance of `outputToken` has increased by at least `minOutputTokenAmount`

If we look at the specific transformer implementations, we can see that they take their data from the `transformations` params and do not have visibility into the `inputToken` or `outputToken`. In addition, many of them transfer the assets directly back to the caller, rather than to the `state.wallet` contract.

As a few examples:
- [PositiveSlippageFeeTransformer.sol](https://github.com/0xProject/protocol/blob/198d986fdc8c65eb7de718dbc277c097cd7a53b7/contracts/zero-ex/contracts/src/transformers/PositiveSlippageFeeTransformer.sol) allows you to send a token, an amount and a recipient, and it will send any balance it holds over the amount to that recipient.
- [PayTakerTransformer.sol](https://github.com/0xProject/protocol/blob/198d986fdc8c65eb7de718dbc277c097cd7a53b7/contracts/zero-ex/contracts/src/transformers/PayTakerTransformer.sol) allows you to specify a list of tokens and amounts, and it will send that amount of each token to the `msg.sender` of the original call.
- [AffiliteFeeTransformer.sol](https://github.com/0xProject/protocol/blob/198d986fdc8c65eb7de718dbc277c097cd7a53b7/contracts/zero-ex/contracts/src/transformers/AffiliateFeeTransformer.sol) takes a list of tokens, amounts and recipients and sends the specified amount of each token to the matching recipient.

In each of these cases, there will be no assets sent back to the `state.wallet` contract.

However, the `transformERC20()` function still checks that our balance of the `outputToken` has increased by at least `minOutputTokenAmount`. However, it is highly possible that other transformations will have caused this increase, or that a user will input `0` for this parameter since it often doesn't matter.

The result is that if a user uses has a token returned by one of these transformers that is not the `outputToken`, it will not be accounted for by Sentiment and will not count towards their account balance. This could result in unfair liquidations, as the user's balance will be lower than it should be.

### Proof of Concept

Here is a test that can be dropped into `0xTransform.t.sol` to demonstrate this issue.

First, add the `IERC20Token` interface to the top of the test file:
```solidity
interface IERC20Token {
    function balanceOf(address) external returns(uint);
}
```
Then, add the `TransformData` struct (used by PayTakerTransformer) to the contract:
```solidity
struct TransformData {
    // The tokens to transfer to the taker.
    IERC20Token[] tokens;
    // Amount of each token in `tokens` to transfer to the taker.
    // `uint(-1)` will transfer the entire balance.
    uint256[] amounts;
}
```
Finally, run the following test to show that the controller returns no tokens in, but the 0x contract returns WETH (not the `outputToken`) to the user:
```solidity
function testMissesOutputTokenInSomeTransformers() public {
    address SENTIMENT_WALLET = address(1234);
    IERC20Token weth = IERC20Token(0x82aF49447D8a07e3bd95BD0d56f35241523fBab1);
    address zeroex = 0xDef1C0ded9bec7F1a1670819833240f027b25EfF;

    // first, we set up the data for the transformation
    IERC20Token[] memory tokens = new IERC20Token[](1);
    tokens[0] = weth;
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 100 ether;
    TransformData memory transformData = TransformData(tokens, amounts);
    ITransformERC20Feature.Transformation[] memory transformations = new ITransformERC20Feature.Transformation[](1);
    transformations[0] = ITransformERC20Feature.Transformation(16, abi.encode(transformData));

    // now we create the data for the call, which we'll use with the controller and the forked 0x contract
    bytes memory data = abi.encodeWithSelector(
        ITransformERC20Feature.transformERC20.selector, ETH, ETH, 0, 0, transformations
    );

    // the controller says there are no tokens in
    (bool canCall, address[] memory tokensIn, address[] memory tokensOut) =
        controllerFacade.canCall(target, true, data);

    assert(tokensIn.length == 0);

    // create a fork and seed the 0x contract with some leftover weth to take
    vm.createSelectFork("INSERT RPC URL");
    deal(address(weth), 0xdB6f1920A889355780aF7570773609Bd8Cb1f498, 100 ether);

    // in reality, we can move our weth balance from zero to non-zero
    assert(weth.balanceOf(SENTIMENT_WALLET) == 0);
    vm.prank(SENTIMENT_WALLET);
    zeroex.call(data);
    assert(weth.balanceOf(SENTIMENT_WALLET) > 0);
}
```

### Recommendation

If you want to interact with 0x without risk, you'll need to get more granular on which transformers are accepted.

This will accomplish two things:

1) You can decode the data passed to the transformer to ensure that all returned tokens are accounted for.

2) By default, you will not support new transformers, which will ensure that you are able to safely add new transformer support, rather than risking being surprised later.

### Review

Acknowledged. The Sentiment front end will only support transactions that follow their expectations.

Further, the worst that can happen to a user is to harm themselves with these actions (they cannot steal funds or harm others). Sentiment will be very clear that transactions outside the front end where tokens are returned that are not `outputToken` are not supported, and users will need to manually add these assets to their accounts if they perform them to avoid risking liquidation.

## [L-01] Aura's `withdraw()` and `redeem()` functions do not send any reward tokens

When the controller sees a call to Aura's `withdraw()` or `redeem()` function, it sets `tokensIn` to an array of the `asset` along with all reward tokens:
```solidity
function canCallWithdrawAndRedeem(address target)
    internal
    view
    returns (bool, address[] memory, address[] memory)
{
    uint256 rewardLength = IRewards(target).extraRewardsLength();
    address[] memory tokensIn = new address[](rewardLength + 2);
    for (uint256 i = 0; i < rewardLength; i++) {
        tokensIn[i] = IRewards(IRewards(target).extraRewards(i)).rewardToken();
    }
    tokensIn[rewardLength] = IERC4626(target).asset();
    tokensIn[rewardLength + 1] = IRewards(target).rewardToken();

    address[] memory tokensOut = new address[](1);
    tokensOut[0] = target;
    return (true, tokensIn, tokensOut);
}
```
However, if we examing the code, we will see that no rewards are sent, so the `tokensIn` array could simply be set to `[asset]`.
```solidity
function _withdrawAndUnwrapTo(uint256 amount, address from, address receiver) internal updateReward(from) returns(bool){
    //also withdraw from linked rewards
    for(uint i=0; i < extraRewards.length; i++){
        IRewards(extraRewards[i]).withdraw(from, amount);
    }

    _totalSupply = _totalSupply.sub(amount);
    _balances[from] = _balances[from].sub(amount);

    //tell operator to withdraw from here directly to user
    IDeposit(operator).withdrawTo(pid,amount,receiver);
    emit Withdrawn(from, amount);

    emit Transfer(from, address(0), amount);

    return true;
}
```
https://github.com/aurafinance/convex-platform/blob/3cd1ce3657bae8abb975b9dd06f28247c22880d3/contracts/contracts/BaseRewardPool.sol#LL269C1-L285C6

We can see that there is no call to withdraw the `rewardToken` of the main pool.

While it seems that there are withdrawals of the `extraRewards`, the `withdraw()` function on those does not actually claim those rewards, it simply uses the `updateReward()` modifier to update the stored rewards waiting to be claimed:
```solidity
function withdraw(address _account, uint256 amount)
    public
    updateReward(_account)
{
    require(msg.sender == address(deposits), "!authorized");
    //require(amount > 0, 'VirtualDepositRewardPool : Cannot withdraw 0');

    emit Withdrawn(_account, amount);
}
```
https://github.com/aurafinance/convex-platform/blob/3cd1ce3657bae8abb975b9dd06f28247c22880d3/contracts/contracts/VirtualBalanceRewardPool.sol#L179-L187

### Recommendation

The `canCallWithdrawAndRedeem()` function can be simplified to only include the `IERC4626(target).asset()` token in the `tokensIn` array.

### Review

Fixed in [commit 49db04366e255568f0cab1e6e083b9fff808b384](https://github.com/sentimentxyz/controller/pull/64/commits/49db04366e255568f0cab1e6e083b9fff808b384) as recommended.

## [L-02] If ETH is used as an input and output token to 0x, it will always revert

When transaction data to `transformERC20()` is decoded, the following check is made:
```solidity
(address tokenOut, address tokenIn) =
    abi.decode(data[4:], (address, address));

if (tokenIn == ETH) {
    tokensOut = new address[](1);
    tokensOut[0] = tokenOut;
    return (true, new address[](0), tokensOut);
}

if (tokenOut == ETH) {
    tokensIn = new address[](1);
    tokensIn[0] = tokenIn;
    return (true, tokensIn, new address[](0));
}
```
The intention is that, if a token going in or out of our sentiment wallet is ETH, we return an empty array. This is because (a) Sentiment balances automatically account for ETH and (b) the address representing ETH (`0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`) is not a real token, so calls to it would revert.

However, in the case where both the `inputToken` and `outputToken` are ETH, the check above fails.

When the first `if` statement is triggered (because `tokenIn == ETH`), we assume the `outputToken` is not ETH and set `tokensOut[0] = tokenOut`.

Since `tokenOut` is ETH, this is returning a token with the value `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` to our account.

Tracing this back through Sentiment, the result is:
- we call `_updateTokensOut()` with `tokensOut` as `[0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE]`
- for each token in `tokensOut`, we call `tokensOut[i].balanceOf(account)`
- since `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` is not a real token, this call reverts

### Proof of Concept

Here is a test that can be dropped into `0xTransform.t.sol` demonstrating this issue:

```solidity
function testEthOutIfAlsoIn() public {
    ITransformERC20Feature.Transformation[] memory transformations = new ITransformERC20Feature.Transformation[](0);
    bytes memory data = abi.encodeWithSelector(
        ITransformERC20Feature.transformERC20.selector, ETH, ETH, 0, 0, transformations
    );

    (bool canCall, address[] memory tokensIn, address[] memory tokensOut) =
        controllerFacade.canCall(target, true, data);

    assert(tokensOut[0] == ETH);
}
```

### Recommendation

Add a nested check to the first `if` statements to ensure this situation is accounted for:
```diff
if (tokenIn == ETH) {
+   if (tokenOut == ETH) return (true, new address[](0), new address[](0));
    tokensOut = new address[](1);
    tokensOut[0] = tokenOut;
    return (true, new address[](0), tokensOut);
}

// no need to check it here because it would already be caught above
if (tokenOut == ETH) {
    tokensIn = new address[](1);
    tokensIn[0] = tokenIn;
    return (true, tokensIn, new address[](0));
}
```

### Review

Acknowledged. This situation seems unlikely to happen, and the Sentiment team has chosen not to address the issue.
