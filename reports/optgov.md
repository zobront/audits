<table>
    <tr>
        <td><img src="https://s2.coinmarketcap.com/static/img/coins/200x200/11840.png" width="250" height="250" /></td>
        <td>
            <h1>Agora Audit Report</h1>
            <h2>Optimism Governor & Approval Voting Module</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: May 10 to 12, 2023</p>
        </td>
    </tr>
</table>

# About **Agora**

Agora is the hub for Nouns governance participants to view delegates and their past activities, share their views, and more.

The Optimism Governor is the governance contract created by Agora to support the Optimism ecosystem.

The Approval Voting Module is a new mechanism that allows any governor to delegate some of its logic to an external module that can implement additional filtering and logic. In this case, the module allows proposals to contain multiple "options" that can be selectively passed based on specific criteria.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Senior Watson at Sherlock, a Security Researcher at Spearbit, and has identified multiple critical severity bugs in the wild, including in a Top 5 Protocol on Immunefi. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

The [voteagora/optimism-gov](https://github.com/voteagora/optimism-gov/) repository was audited at commit [35f441738bd7864bd37949a40842486bc0ac51b0](https://github.com/voteagora/optimism-gov/commit/35f441738bd7864bd37949a40842486bc0ac51b0).

The following contracts were in scope:
- src/OptimismGovernorV5.sol
- src/modules/VotingModule.sol
- src/modules/ApprovalVotingModule.sol

After completion of the fixes, the TK commit was reviewed.

# Summary of Findings

| ID     | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [H-01] | Proposals supported only by a small fraction of the community can be passed using the Approval Module | High | ✓ |
| [H-02] | Budget cap will not account for transfers of approved or permitted ERC20 tokens | High | ✓ |
| [M-01] | New proposals can be DOS'd by frontrunning |  Medium | ✓ |
| [M-02] | Any address can be passed as a VotingModule, which could lead to abuse | Medium | ✓ |
| [M-03] | Votes can be arbitrarily extended by Manager until they meet quorum | Medium | |
| [L-01] | Quorum initialized to 0.03% instead of 30% due to overridden denominator | Low | ✓ |
| [G-01] | Loops in ApprovalVotingModule#propose() can be consolidated | Gas | ✓ |
| [G-02] | Remove checks for inaccessible states | Gas | ✓ |

# Detailed Findings

## [H-01] Proposals supported only by a small fraction of the community can be passed using the Approval Module

When a new proposal is created through `OptimismGovernorV5.sol`, there are two options for the proposer:

1) `propose()`: This uses the usual `governor` proposal process, which requires quorum to be met (`yes votes + abstain votes >= quorum`) and the vote to succeed (`yes votes > no votes`).

2) `proposeWithModule()`: This will call out to the passed `module` with proposer-defined parameters that are required in order for the proposal to pass, with the ability for certain "options" to pass while others fail. It require those parameters to be met, as well as quorum to be met (`yes votes + abstain votes >= quorum`).

The problem lies in the fact that using `proposeWithModule()` actually loosens the minimum parameters to get proposals passed because it doesn't allow `no` votes and replaces that with proposer-defined logic.

The only firm requirement for a proposal as a whole to go ahead is for quorum to be met. Beyond that, decisions are delegated to the logic passed to the module.

Because this logic is defined by the proposer, they can set it up in such a way as to make the proposal pass much more easily than it should, which can allow a small minority of the community to pass proposals the rest of the community does not want.

### Proof of Concept

- There is a controversial issue that 10% of the community supports vehemently, while 90% strongly dislikes.
- Through the normal proposal process, such an issue would have no hope of passing, because `yes votes > no votes` could not be accomplished.
- However, a community member that wants to see such a vote succeed could call `proposeWithModule()` and set the criteria to "top choices" with this as the only option.
- Because there is no way to vote "no" on a module proposal, the 90% who disagree are best served by doing nothing.
- The only requirements on the remaining 10% are that (a) the option gets at least 1 vote and (b) the overall proposal reached quorum.
- Quorum is currently set to ~3%, so it would easily pass.
- The result is that a small minority of community members were able to easily pass a proposal.

Of course, at the moment, such an attack could only be performed by the `manager`, since proposing is restricted. But when the contract opens up to community proposals, this issue would imply that any holder of more than 3% of OP tokens can pass any proposal they would like.

### Recommendation

Ensure that the requirements to pass a proposal through the module are always greater than or equal to the normal proposal proposal process.

In this case, that means ensuring there is the ability to vote `no` on the proposal as a whole, and that the whole proposal will fail if `yes votes <= no votes`.

### Review

Fixed in commit [41d5fd3f460a9fbe3298b967c360795a67de5cfe](https://github.com/voteagora/optimism-gov/commit/41d5fd3f460a9fbe3298b967c360795a67de5cfe) by refactoring `OptimismGovernorV5.sol` to continue to use the regular voting logic, and only using the module for additional logic in determining vote success and execution params.


## [H-02] Budget cap will not account for transfers of approved or permitted ERC20 tokens

`ApprovalVotingModule.sol` contains a feature where the governor can input a `budgetToken` and a `budgetAmount`, and the module ensures that passed proposals cannot spend more than this amount of this token.

This check occurs in `_formatExecuteParams()`. In this function, we loop over all of the transaction options that met the criteria, tally up the amount of budget token spent, and break the loop if the amount spent crosses the budget.

It is implemented as follows:
```solidity
for (n = 0; n < option.targets.length;) {
    // Shortcircuit if `budgetAmount` is exceeded
    if (settings.budgetAmount != 0) {
        if (settings.budgetToken == address(0)) {
            // If `budgetToken` is ETH and value is not zero, add msg value to `totalValue`
            if (option.values[n] != 0) totalValue += option.values[n];
        } else {
            // If `target` is `budgetToken` and calldata is not zero
            if (settings.budgetToken == option.targets[n]) {
                bytes memory data = option.calldatas[n];
                if (data.length != 0) {
                    uint256 amount;
                    // If it's a `transfer` or `transferFrom`, add `amount` to `totalValue`
                    if (bytes4(data) == IERC20.transfer.selector) {
                        assembly {
                            // Load the last 32 bytes of `data` into 'amount'
                            amount := mload(add(data, 0x44))
                        }
                    } else if (bytes4(data) == IERC20.transferFrom.selector) {
                        assembly {
                            // Load the last 32 bytes of `data` into 'amount'
                            amount := mload(add(data, 0x64))
                        }
                    }
                    if (amount != 0) totalValue += amount;
                }
            }
        }

        // Break loop if `budgetAmount` is exceeded
        if (totalValue > settings.budgetAmount) break;
    }

    unchecked {
        executeParams[executeParamsLength + n] =
            ExecuteParams(option.targets[n], option.values[n], option.calldatas[n]);

        ++n;
    }
}
```
[ApprovalVotingModule.sol#L206-L284](https://github.com/voteagora/optimism-gov/blob/35f441738bd7864bd37949a40842486bc0ac51b0/src/modules/ApprovalVotingModule.sol#L206-L284)

For ERC20 tokens, this code increments the `totalValue` only when the following conditions are met:
- the `target` for the transaction is the ERC20 token itself
- the function selector is `transfer()` or `transferFrom()`

However, these conditions do not succeed in accomplishing their goal. Most importantly, they miss two extremely common patterns for ERC20 transfers. Additionally, they may count spent tokens that should not be.

1) `approve()` & `transferFrom()`: The most common way for contracts to interact with other contracts that require ERC20 tokens for payment is to first call `approve()` and then call a function on the other contract, which calls `transferFrom()`. In this case, because the first call is using the `approve()` selector and the second is to another contract, `totalValue` will not be incremented.

2) `permit()`: An alternative rising in popularity is the `permit()` method, which allows passing a signature to another contract that can be used to first approve transfers on your behalf, and then perform `transferFrom()`. Such a function call will not interact with the ERC20 directly at all, so will not trigger the budget incrementer.

3) non-spending `transferFrom()`: The budget count is currently triggered when the contract calls `transferFrom()` on the `budgetToken`, but in many cases, this could be transferring the tokens of another user, not the contract itself. In this case, the `totalValue` would be incremented by the amount sent, which is most likely not the intended behavior.

### Recommendations

- Check the initial balance of the ERC20 before beginning execution.
- Have the proposal include a `tokenBudget` for each action.
- Tally up these `tokenBudget` values, and reject any push the total over the `budgetAmount`.
- After the proposal has been executed, check the final balance of the ERC20, and ensure that it hasn't fallen by more than it should have based on the sum of `tokenBudget`s.

### Review

Fixed as recommended in [39880bd56c99a83b5df3fafbc3c6d35f104a1cda](https://github.com/voteagora/optimism-gov/commit/39880bd56c99a83b5df3fafbc3c6d35f104a1cda).

## [M-01] New proposals can be DOS'd by frontrunning

To create a new proposal using the `ApprovalVotingModule`, the Manager of the governor contract calls `proposeWithModule()`:

```solidity
function proposeWithModule(VotingModule module, bytes memory proposalData, string memory description)
    public
    onlyManager
    returns (uint256)
{
    require(
        getVotes(_msgSender(), block.number - 1) >= proposalThreshold(),
        "Governor: proposer votes below proposal threshold"
    );

    uint256 proposalId = hashProposalWithModule(address(module), proposalData, keccak256(bytes(description)));

    ProposalCore storage proposal = _proposals[proposalId];
    require(proposal.voteStart.isUnset(), "Governor: proposal already exists");

    uint64 snapshot = block.number.toUint64() + votingDelay().toUint64();
    uint64 deadline = snapshot + votingPeriod().toUint64();

    proposal.voteStart.setDeadline(snapshot);
    proposal.voteEnd.setDeadline(deadline);
    proposal.votingModule = address(module);

    emit ProposalCreated(proposalId, _msgSender(), address(module), proposalData, snapshot, deadline, description);

    module.propose(proposalId, proposalData);

    return proposalId;
}
```
[OptimismGovernorV5.sol#L77-L104](https://github.com/voteagora/optimism-gov/blob/35f441738bd7864bd37949a40842486bc0ac51b0/src/OptimismGovernorV5.sol#L77-L104)

The `proposalId` is set using the `hashProposalWithModule()` function:
```solidity
function hashProposalWithModule(address module, bytes memory proposalData, bytes32 descriptionHash)
    public
    view
    virtual
    returns (uint256)
{
    return uint256(keccak256(abi.encode(address(this), module, proposalData, descriptionHash)));
}
```
[OptimismGovernorV5.sol#L279-L286](https://github.com/voteagora/optimism-gov/blob/35f441738bd7864bd37949a40842486bc0ac51b0/src/OptimismGovernorV5.sol#L279-L286)

If we follow the call to `module.propose()`, we see the following:
```solidity
function propose(uint256 proposalId, bytes memory proposalData) external override {
    if (_proposals[proposalId].governor != address(0)) revert ExistingProposal();
    ...
}
```
[ApprovalVotingModule.sol#L107-L109](https://github.com/voteagora/optimism-gov/blob/35f441738bd7864bd37949a40842486bc0ac51b0/src/modules/ApprovalVotingModule.sol#L107-L109)

This function allows any address (presumably a governor) to call `propose()` and confirms that the `proposalId` has not been used before. Since the hash includes the address of the governor, it is assumed that this hash will be unique across governors using the `ApprovalVotingModule`.

However, there is no check that the `proposalId` submitted is actually equal to the output of `hashProposalWithModule`, nor are there any protections on who can call this function.

As a result, a malicious user can watch the mempool for new calls to `proposeWithModule()`, calculate the `proposalId` from the data, and frontrun the call to `module.propose()` with the same `proposalId`.

The result is that a proposal will be created on the `ApprovalVotingModule` with the malicious user set as the governor, and the legitimate call from the governor will revert.

This can be continued endlessly, blocking any proposals from being created.


### Recommendation

The uniqueness of the `proposalId` should be enforced on the `ApprovalVotingModule` side, rather than on the governor side.

Rather than simply passing the `proposalId` to the module, the module should take in the underlying data and compute the `proposalId` itself.

To ensure that `proposalId`s match between the governor and the module, the safest option is to pass the `proposalId` as well as all necessary values to compute it and check on the module that they align, as follows:
```solidity
function propose(uint256 proposalId, bytes memory proposalData, bytes32 descriptionHash) external override {
        if (
            proposalId != uint256(keccak256(abi.encode(msg.sender, address(this), proposalData, descriptionHash)))
        ) revert WrongProposalId();

        if (_proposals[proposalId].governor != address(0)) revert ExistingProposal();

        ...
}
```

This serves the purpose of ensuring that the `msg.sender` is equal to the governor address value that should be included in the hash, and blocks the ability for arbitrary users to submit `proposalId`s they should not be able to create.

[Note that there is also the (very unlikely) case that two governors may use different hash functions to determine their `proposalId`s and could end up colliding that way, and this fix addresses this risk as well.]

### Review

Fixed as recommended in [20e645198d10646c6923e8a9caafb05e536d8fe3](https://github.com/voteagora/optimism-gov/commit/20e645198d10646c6923e8a9caafb05e536d8fe3).

## [M-02] Any address can be passed as a VotingModule, which could lead to abuse

In `OptimismGovernorV5.sol`, the `proposeWithModule()` function has the following signature:
```solidity
function proposeWithModule(VotingModule module, bytes memory proposalData, string memory description);
```
This allows the caller to input a `VotingModule` address, and that module will be used to:
- set up the proposal (`module.propose()`)
- return the execution data (`module._formatExecuteParams()`)
- determine if a user has already voted (`module.hasVoted()`)
- determine if quorum has been reached (`module._quorumReached()`)
- determine whether a vote succeeded (`module._voteSucceeded()`)

It is assumed that the proposer will enter a valid module that does these things fairly, but there is no check to be sure.

This could be abused in a number of ways, but the most malicious and difficult to catch would be to create a module that operates normally but returns malicious data (unrelated to the proposal) from `module._formatExecuteParams()`. Then one could pass an innocent looking proposal, and when it was executed, a completely different transaction would be run. This could be used to perform unwanted actions or steal funds.

While this risk is diminished at the moment because proposals can only be created by the `manager`, it does add some risk at present and will become Critical when governance is opened up to proposals from the community.

### Recommendation

Create an allowlist of modules that are permitted to be used by the governor, and check that the module is on that list when new proposals are being created.

Fortunately, because the module address is hashed into the `proposalId`, once this value is checked once, it will not need to be checked each time the module is passed.

### Review

Fixed as recommended in [1152881afcb6272a29e80b0cb17914007a68cd27](https://github.com/voteagora/optimism-gov/commit/1152881afcb6272a29e80b0cb17914007a68cd27).

## [M-03] Votes can be arbitrarily extended by Manager until they meet quorum

In `OptimismGovernorV5.sol`, new proposals are created with a `snapshot` (start time) and `deadline` (end time):

```solidity
uint64 snapshot = block.number.toUint64() + votingDelay().toUint64();
uint64 deadline = snapshot + votingPeriod().toUint64();

proposal.voteStart.setDeadline(snapshot);
proposal.voteEnd.setDeadline(deadline);
proposal.votingModule = address(module);
```
All significant parameters on a proposal are locked once the vote is underway:
- a proposal's `votingModule` is immutable and cannot be changed
- updates to `quorum` are saved historically, so that updates don't change existing proposals
- `votingPeriod` and `votingDelay` cannot impact timing because calculations are performed up front and saved
- all settings and options are immutably set and cannot be changed

The one exception is the `proposalDeadline`, which can be edited by the Manager with this function:
```solidity
function setProposalDeadline(uint256 proposalId, uint64 deadline) public onlyManager {
    _proposals[proposalId].voteEnd.setDeadline(deadline);
    emit ProposalDeadlineUpdated(proposalId, deadline);
}
```
This allows the manager to extend the vote for an arbitrary amount of time by continually pushing back the deadline.

This is especially risky when using the `ApprovalVotingModule`, because there are no `Against` votes. If many users are against the proposal, there is no way for them to express their opinion except by not voting. However, extending the vote will inevitably lead to more awareness and a vote that is more likely to pass (either by reaching quorum or by individual options reaching their threshold).

In an extreme case, a Manager could even push back the deadline for a completed vote, reopening it after the fact. In fact, failed votes can be moved from `Defeated` to `Active` at any time. This breaks a strong user assumptions, as votes should be considered final once they are completed.

### Recommendation

Only allow the deadline to be changed before the vote starts:
```diff
function setProposalDeadline(uint256 proposalId, uint64 deadline) public onlyManager {
+   require(block.timestamp < _proposals[proposalId].voteStart.getDeadline());
    _proposals[proposalId].voteEnd.setDeadline(deadline);
    emit ProposalDeadlineUpdated(proposalId, deadline);
}
```

### Review

Acknowledged: "Currently leaving this unchanged as `setProposalDeadline` is intended to be unrestricted in this version."

## [L-01] Quorum initialized to 0.03% instead of 30% due to overridden denominator

When `OptimismGovernorV5.sol` is initialized, the `quorumNumerator` is set to `30`:

```solidity
function initialize(IVotesUpgradeable _votingToken, address _manager) public initializer {
    __Governor_init("Optimism");
    __GovernorCountingSimple_init();
    __GovernorVotes_init(_votingToken);
    __GovernorVotesQuorumFraction_init({quorumNumeratorValue: 30});
    __GovernorSettings_init({initialVotingDelay: 6575, initialVotingPeriod: 46027, initialProposalThreshold: 0});

    manager = _manager;
}
```
This value is intended to represent a 30% quorum when the denominator is set to 100, which is the default value set by OpenZeppelin and is represented in [GovernorVotesQuorumFractionUpgradeableV2.sol#L68-L70](https://github.com/voteagora/optimism-gov/blob/35f441738bd7864bd37949a40842486bc0ac51b0/src/lib/v2/GovernorVotesQuorumFractionUpgradeableV2.sol#L68)
```solidity
function quorumDenominator() public view virtual returns (uint256) {
    return 100;
}
```
However, this value is overriden in `OptimismGovernorV5.sol`:
```solidity
function quorumDenominator() public view virtual override returns (uint256) {
    // Configurable to 3 decimal points of percentage
    return 100_000;
}
```
When quorum is calculated, we perform the following math:
```solidity
function quorum(uint256 blockNumber) public view virtual override returns (uint256) {
    return (token.getPastTotalSupply(blockNumber) * quorumNumerator(blockNumber)) / quorumDenominator();
}
```
The result is that the quorum is represented as `tokenSupply * 30 / 100_000 = tokenSupply * 0.0003`, or 0.03% of supply.

### Proof of Concept

The following test can be dropped in to `OptimismGovernorV5.t.sol` to show the error:
```solidity
    function testZachQuorumCalculationIncorrect() public {
        uint256 snapshot = block.number + governor.votingDelay();
        vm.roll(snapshot + 1);

        console2.log(op.getPastTotalSupply(snapshot));
        console2.log(governor.quorum(snapshot));
    }
```
```
Logs:
  101000000000000000000 // total supply
  30300000000000000 // quorum (= 0.03% of total supply)
```

### Recommendation

Change the value set in in the `initialize()` function to `30_000` to represent 30%:
```diff
```solidity
function initialize(IVotesUpgradeable _votingToken, address _manager) public initializer {
    __Governor_init("Optimism");
    __GovernorCountingSimple_init();
    __GovernorVotes_init(_votingToken);
-   __GovernorVotesQuorumFraction_init({quorumNumeratorValue: 30});
+   __GovernorVotesQuorumFraction_init({quorumNumeratorValue: 30_000});
    __GovernorSettings_init({initialVotingDelay: 6575, initialVotingPeriod: 46027, initialProposalThreshold: 0});

    manager = _manager;
}
```

### Review

Fixed by removing the `initialize()` function (since the proxy has already been initialized and is just being upgraded) in [6aa306ea5df526bd49e88073daa0da27c5b56e5e](https://github.com/voteagora/optimism-gov/commit/6aa306ea5df526bd49e88073daa0da27c5b56e5e)

## [G-01] Loops in ApprovalVotingModule#propose() can be consolidated

In the `propose()` function in `ApprovalVotingModule.sol`, we perform the following two loops:

```solidity
unchecked {
    // Ensure proposal params of each option have the same length between themselves
    ProposalOption memory option;
    for (uint256 i; i < optionsLength; ++i) {
        option = proposalOptions[i];
        if (option.targets.length != option.values.length || option.targets.length != option.calldatas.length) {
            revert InvalidParams();
        }
    }

    // Push proposal options in storage
    for (uint256 i; i < optionsLength; ++i) {
        _proposals[proposalId].options.push(proposalOptions[i]);
    }
}
```
Since these two loops are iterating over the same elements, they can be consolidated into one loop.

### Proof of Concept

Using the built in test suite's `testProposeWithModule()` function, we can see the following improvement in gas cost:
```
CURRENT IMPLEMENTATION
Running 1 test for test/OptimismGovernorV5.t.sol:OptimismGovernorV5Test
[PASS] testProposeWithModule() (gas: 722324)
Test result: ok. 1 passed; 0 failed; finished in 6.96ms

CONSOLIDATED LOOPS
Running 1 test for test/OptimismGovernorV5.t.sol:OptimismGovernorV5Test
[PASS] testProposeWithModule() (gas: 722048)
Test result: ok. 1 passed; 0 failed; finished in 2.41ms
```
Since this test only uses 2 options, the improvement is minor (`722324 - 722048 = 276`), but this value would be multiplied in proposals with more options.

### Recommendation

```solidity
unchecked {
    // Ensure proposal params of each option have the same length between themselves
    ProposalOption memory option;
    for (uint256 i; i < optionsLength; ++i) {
        option = proposalOptions[i];
        if (option.targets.length != option.values.length || option.targets.length != option.calldatas.length) {
            revert InvalidParams();
        }
        _proposals[proposalId].options.push(option);
    }
}
```

### Review

Fixed as recommended in [a89a51559f3b116c60703b2acb2c48bf51121692](https://github.com/voteagora/optimism-gov/commit/a89a51559f3b116c60703b2acb2c48bf51121692).

## [G-02] Remove checks for inaccessible states

`GovernorUpgradeableV2.sol` has a simplified `state()` function that can not reach every possible `ProposalState`.

Here is the enum with the list of possible states:
```solidity
enum ProposalState {
    Pending,
    Active,
    Canceled,
    Defeated,
    Succeeded,
    Queued,
    Expired,
    Executed
}
```
Here is the function, which assigns the state:
```solidity
function state(uint256 proposalId) public view virtual override returns (ProposalState) {
    ProposalCore storage proposal = _proposals[proposalId];

    if (proposal.executed) {
        return ProposalState.Executed;
    }

    if (proposal.canceled) {
        return ProposalState.Canceled;
    }

    uint256 snapshot = proposalSnapshot(proposalId);

    if (snapshot == 0) {
        revert("Governor: unknown proposal id");
    }

    if (snapshot >= block.number) {
        return ProposalState.Pending;
    }

    uint256 deadline = proposalDeadline(proposalId);

    if (deadline >= block.number) {
        return ProposalState.Active;
    }

    if (_quorumReached(proposalId) && _voteSucceeded(proposalId)) {
        return ProposalState.Succeeded;
    } else {
        return ProposalState.Defeated;
    }
}
```
As we can see, Pending, Active, Canceled, Defeated, Succeeded, and Executed states are possible to be reached. However, Queued and Expired are not.

Because much of our function logic is borrowed from versions of the contract where these states were reachable, these values are still checked. We can save some gas by removing the checks for these unreachable states from our functions.

### Recommendation

In `OptimismGovernorV5.sol#executeWithModule()`, we can remove the check for `Queued`:
```solidity
require(
    status == ProposalState.Succeeded || status == ProposalState.Queued, "Governor: proposal not successful"
);
```
In `OptimismGovernorV5.sol#cancelWithModule()`, we can remove the check for `Expired`:
```solidity
require(
    status != ProposalState.Canceled && status != ProposalState.Expired && status != ProposalState.Executed,
    "Governor: proposal not active"
);
```
In `GovernorUpgradeableV2.sol#execute()`, we can remove the check for `Queued`:
```solidity
require(
            status == ProposalState.Succeeded || status == ProposalState.Queued, "Governor: proposal not successful"
        );
```
In `GovernorUpgradeableV2.sol#_cancel()`, we can remove the check for `Expired`:
```solidity
require(
    status != ProposalState.Canceled && status != ProposalState.Expired && status != ProposalState.Executed,
    "Governor: proposal not active"
);
```

### Review

Fixed as recommended in [cf1a0ded961f6c617642bb00ed14e3ca87a7a715](https://github.com/voteagora/optimism-gov/commit/cf1a0ded961f6c617642bb00ed14e3ca87a7a715).
