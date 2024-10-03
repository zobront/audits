<table>
    <tr><th></th><th></th></tr>
    <tr>
        <td><img src="https://img.cryptorank.io/coins/succinct1711041465331.png" width="250" height="250" /></td>
        <td>
            <h1>Succinct Audit Report</h1>
            <h2>OP Succinct ZKL2OutputOracle</h2>
            <p>Prepared by: Zach Obront, Independent Security Researcher</p>
            <p>Date: Monday August 19th, 2023</p>
        </td>
    </tr>
</table>

# About **OP Succinct**

OP Succinct is an implementation of the OP Stack that upgrades the chain to use ZK Validity Proofs. The ZKL2OutputOracle contract is a small diff to Optimism's L2OutputOracle contract that requires ZK proofs in order to progress the chain.

# About **zachobront**

Zach Obront is an independent smart contract security researcher. He serves as a Lead Security Researcher at Spearbit, a Lead Senior Watson at Sherlock, and has identified multiple critical severity bugs in the wild. You can say hi on Twitter at [@zachobront](http://twitter.com/zachobront).

# Summary & Scope

The [succinctlabs/op-succinct](https://github.com/succinctlabs/op-succinct/) repo was audited at commit [dd507f775b5c43b17d56d7039a1db71a92ab3475](https://github.com/succinctlabs/op-succinct/commit/dd507f775b5c43b17d56d7039a1db71a92ab3475).

The following contract was in scope, with an assumption that all dependencies (especially the program being proven and the SP1Verifier contract used for proof verification) were correct:
- contracts/src/ZKL2OutputOracle.sol

# Summary of Findings

| Identifier     | Title                        | Severity      | Fixed |
| ------ | ---------------------------- | ------------- | ----- |
| [L-01] | Impossible to verify blocks can permanently halt the chain | Low | ✓ |
| [L-02] | Owner can insert faulty roots by manipulating the `vkey` or `verifierGateway` | Low | ✓ |

# Detailed Findings


## [L-01] Impossible to verify blocks can permanently halt the chain

When the contract is deployed, the first entry to `l2Outputs` is manually added. After this, the only possible way to add entries is to call `proposeL2Output()`. This function calls `verifierGateway.verifyProof()` to verify the proof.

In the event that there is some bug that causes an individual block to be unable to be proven, the chain will be unable to progress past this block and will remain permanently halted.

### Recommendation

Implement some mechanism for governance or a security council to manually override the output root in case of emergency.

### Review

This can be mitigated by either (a) setting the `owner` to a Security Council and using [L-02] to manipulate the chain past this block or (b) upgrading the contract to an implementation that allows for a new output root to be manually added upon initialization.

## [L-02] Owner can insert faulty roots by manipulating the `vkey` or `verifierGateway`

While the contract does not seem to intentionally allow the owner or proposer to skip the ZK validity check, the owner does have the power to change the `vkey` or `verifierGateway` values.

Either of these values can be used to allow an arbitrary output root to be added to the chain:
- The `verifierGateway` can be changed to an address that never reverts when `verifyProof()` is called (or reverts for anything but the desired output root).
- The `vkey` can be changed to the vkey of a program that always return `true` (or returns `true` for the desired output root only).

### Recommendation

Ensure that users are aware that whatever address is set as `owner` on the contract has the ability to push output roots past the ZK check, regardless of their validity.

### Review

This is intended behavior. If a protocol wishes to remove any centralized power, they can simply set `owner` to the zero address. Alternatively, if they wish to give this power only to the community, they can set `owner` to their governance executor or a Security Council.
