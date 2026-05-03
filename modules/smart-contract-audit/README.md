# Smart Contract Audit Module

Specialized deep-audit module for Solidity smart contracts and (extending) Solana / Move modules. Sits alongside the main Preston-Check catalog but operates with a different lens: **a smart contract under audit gets days or weeks of attention; a fintech codebase gets minutes per scan**. The deliverable formats are correspondingly different — this module produces narrative-friendly audit reports, optional symbolic-execution and fuzzing output, and integrates with Slither, Mythril, and Echidna when those tools are available.

## What this module covers

**Phase 1** — Solidity catalog checks from the main suite (P-301..P-310, P-348..P-353, P-356) — reentrancy, integer overflow, tx.origin auth, unbounded loops, DEX slippage, oracle manipulation, unbounded approvals, bridge replay, stablecoin peg, governance time-locks, proxy upgrade safety, EIP-2612 permit replay, account abstraction safety, comprehensive access control, flash loan attack resistance, unchecked external calls, liquidation safety. Plus the Solana / Move suite (P-510..P-517) when applicable.

**Phase 2** — Deep smart-contract audit checks (P-700..P-719), a new tier of patterns specific to dedicated audit work:

| ID | Check | Severity |
|---|---|---|
| P-700 | Storage Layout Collision (proxy upgrades) | critical |
| P-701 | Initializer Function Protection | critical |
| P-702 | Selfdestruct Vulnerability (EIP-6049 deprecation) | high |
| P-703 | Delegatecall to Untrusted Address | critical |
| P-704 | Front-Running and Mempool Exposure | medium |
| P-705 | Cross-Contract Reentrancy | high |
| P-706 | ERC-20 Approve Race Condition | medium |
| P-707 | ERC-721 / ERC-1155 Callback Reentrancy | high |
| P-708 | Token Economics Math (rounding, truncation) | high |
| P-709 | Governance Attack Vectors (vote buying, single-block) | critical |
| P-710 | Cross-Chain Replay in HTLC / Escrow IDs | high |
| P-711 | On-Chain Preimage Storage (cross-chain front-run) | high |
| P-712 | Refund / Claim Authorization Missing | critical |
| P-713 | Timelock Bypass via && Instead of \|\| | critical |
| P-714 | Emergency Pause Missing on Fund-Holding Contract | high |
| P-715 | Critical Immutable Address Without Rotation Path | high |
| P-716 | Unbounded Array Iteration (Gas DoS) | high |
| P-717 | keccak256 abi.encodePacked Collision Risk | medium |
| P-718 | Untrusted bytes Storage Without Length Cap | medium |
| P-719 | Insecure Randomness from Block Data | high |

Each check is grounded in a real-world incident or production audit finding: P-700 references storage-collision proxy upgrade incidents, P-701 cites the Wormhole bridge ($320M, Feb 2022), P-708 cites the Cetus integer overflow on Sui (May 2025, ~$220M), P-709 cites Beanstalk Farms ($182M, April 2022). The P-710..P-719 series codifies lessons from the digital_escrow / Bloxcross HTLC + atomic-swap launches: cross-chain ID binding (HTLC final audit §1.6), preimage non-storage (SC-C2), refund authorization (SC-C1), timelock-bypass predicates (SwapEscrow SC-C1), asymmetric emergency pause (SC-H2), handler rotation timelocks (SC-C3), gas-DoS bounds on held-deposit arrays, abi.encodePacked collision avoidance (SWC-133 / §7.4), bytes-length caps (MPCShard M-6), and block-data randomness misuse.

**Phase 3** — Optional heavyweight tool integrations:

- **Slither** static analysis — dataflow-aware reentrancy, uninitialized state, shadowing, divergent compiler behavior. Runs in seconds.
- **Mythril** symbolic execution — deeper transaction-ordering, complex reentrancy chains, EVM-level invariants. Runs in minutes per contract.
- **Echidna** fuzzing — property-based testing of user-defined invariants. Runs in tens of minutes; requires invariants in `echidna_*` functions in the contracts.

## Usage

```bash
# Quick run (catalog + deep checks; Slither/Mythril/Echidna disabled)
modules/smart-contract-audit/audit.sh /path/to/contracts

# Save audit report
modules/smart-contract-audit/audit.sh --report sc-audit.md /path/to/contracts

# Add Slither (~30s extra)
modules/smart-contract-audit/audit.sh --slither /path/to/contracts

# Full audit pass (Slither + Mythril; minutes per contract)
modules/smart-contract-audit/audit.sh --slither --mythril /path/to/contracts

# Maximum depth (adds Echidna fuzzing if invariants are defined)
modules/smart-contract-audit/audit.sh --slither --mythril --echidna /path/to/contracts
```

## Integration with the main scanner

The main `preston-check.sh` runner can invoke this module as a sub-scan:

```bash
preston-check --module smart-contract-audit /path/to/contracts
```

(That flag is on the v1.7 roadmap; for now invoke `modules/smart-contract-audit/audit.sh` directly.)

## When to use this module

**Use the main scanner** for:
- Pre-deploy CI gates on a fintech codebase (seconds-to-minutes runtime)
- Compliance evidence generation (PCI-DSS, SOC 2, etc.)
- General-purpose security hygiene across a polyglot codebase

**Use this module** for:
- Pre-launch audit of a new smart contract or DeFi protocol
- Post-incident review where you want every relevant check class
- Bug-bounty preparation (run the same checks bounty hunters will run)
- Regulatory submission requiring a deep contract-level security report

## Roadmap

**v1.7** — ✅ Shipped P-710..P-719: cross-chain replay, on-chain preimage, refund authorization, timelock-bypass predicates, emergency pause, immutable rotation, unbounded iteration, encodePacked collision, bytes length cap, block-data randomness — all derived from production audit findings on the digital_escrow HTLC / atomic-swap stack.

**v1.8** — Add P-720..P-729: oracle latency, flash-loan governance, multi-sig threshold validation, yield-farming math, liquidity-pool invariants, lending-protocol parameter validation, ERC-4626 vault correctness, MEV-resistance pattern checks, formal-verification annotation parsing.

**v1.9** — Native invariant DSL: write Echidna-style invariants in YAML/JSON alongside the contract, the module compiles them to Echidna fuzz tests automatically.

**v2.0** — AI-assisted audit narrative generation. Given the structured findings, generate an auditor-facing narrative report following the standard sections (executive summary, scope, findings by severity, recommendations, appendix). Uses `lib/ai_analyze.sh` from the main repo.

## Why a separate module

The deliverable format differs. A pre-deploy security gate produces pass/fail tables; a contract audit produces narrative findings with severity, exploit scenario, recommendation, and code remediation. The audit report is what protocol teams hand to their community before deploying.

The runtime profile differs. A fintech codebase scan completes in 30 seconds. A serious contract audit running Slither + Mythril + Echidna can take an hour for a meaningful protocol. Separating the runners avoids slowing the main pre-deploy gate.

The audience differs. The main scanner serves fintech engineers and CISOs. The audit module serves protocol auditors, bug-bounty hunters, and DAO governance committees. Keeping them as separate entry points lets each have an opinionated UX.
