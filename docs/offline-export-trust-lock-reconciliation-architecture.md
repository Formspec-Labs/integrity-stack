# Offline registry pin lock reconciliation — architecture disposition

**VERDICT: APPROVE the mechanical lock amendment.** It adds the missing `stack-common-typeid → rand_core` dependency edge already declared by the owning manifest. Production code, tests, CLI manifest and usage documentation retain their previously reviewed hashes. Prior code/architecture reviews remain applicable to unchanged code; this addendum supersedes only the architecture certificate's old lock-file identity. No compilation or test PASS follows from metadata success.

## Scope and method

Independent reviewer `/root/handoff_before_review`, parent-requested gpt-6.1-sol/medium; runtime model identity not independently exposed. Applied the full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md`, read in full during this continuous AFTER review. All six phases are addressed below proportionately to a one-edge dependency reconciliation. Only this certificate written. No Cargo, metadata, native build, test or live operation executed by reviewer.

Base Integrity HEAD remains `d2dd4827cd294aaecc470e6a49dd8954a48880cf`. Current `Cargo.lock` diff against that base has precisely two added dependency-list entries: previously approved `integrity-verify-cli → integrity-cbor` and newly reconciled `stack-common-typeid → rand_core`. No package version/checksum/source change appears in this scoped diff.

| Exact current file | SHA256 |
| --- | --- |
| integrity-stack/crates/integrity-verify-cli/Cargo.lock | `56ec53960141ff5a23cf086a54e57cf8e8743c9377d345916de88abb9d05c29e` |
| integrity-stack/crates/integrity-verify-cli/Cargo.toml | `a6c417ccf3dbe5c0de2689f7fc0722dc17384ba4d216a7811b882125f39e4b3a` |
| stack-common/crates/stack-common-typeid/Cargo.toml | `f3a86cfb050d482b45610a0919e56feee18d1bcdf9669c2c4113a269d1e25692` |
| integrity-stack/crates/integrity-verify-cli/src/cli.rs | `ac83297d007c7dec421a72065d9ef7796dbd56a11d554ca91225d405f7402eb9` |
| integrity-stack/crates/integrity-verify-cli/tests/verify_bundle.rs | `addf2343978168bb92439332db0af34ae0dbcfb19de6908580a854aa19bc2ea8` |
| integrity-stack/docs/offline-export-registry-pin.md | `1ee7d1511a3b4d8cb2109a92df621d78c99ce575db6b2f87d450107d945548c2` |

Hashes independently recomputed. Paths are relative to `/Users/mikewolfd/Work/formspec-stack`.

## Lineage, relationships and invariants

The parent decision is `docs/offline-export-trust-after-architecture.md:§§2–7`: narrow CLI admission with maintained native verification and unexecuted-test limits. Its earlier lock hash `c3549e67…` is historical. The owning `stack-common-typeid/Cargo.toml:8` already declares `rand_core` version0.6 with getrandom/std; lock reconciliation records that existing declaration. It does not introduce a new randomness requirement through this CLI feature. Dependency ownership remains with stack-common; CLI stays a consumer through its existing dependency closure.

| Invariant / relationship | Disposition | Evidence |
| --- | --- | --- |
| Owning manifest determines dependencies | PRESERVED | Existing stack-common-typeid manifest declaration now represented in lock dependency list |
| Narrow registry-pin architecture unchanged | PRESERVED | Production/test/CLI manifest/document hashes match prior certificate |
| No package upgrade or new source selection | PRESERVED within inspected amendment | Lock diff adds edges only |
| Execution evidence is distinct from metadata | PRESERVED | Owner reports initial exit101 before compilation and later host-filtered metadata success only |

Hypothesis H1(high), lock amendment changes CLI trust behavior: **REFUTED** by unchanged code and one transitive edge. H2(high), lock amendment represents existing owner declaration: **CONFIRMED** by manifest. H3(high), metadata success qualifies tests: **REFUTED**; resolution and execution are different operations.

## User value and counterfactual

The amendment removes a stale resolution obstacle to a later coordinated native attempt without changing the user-visible verification behavior. No runtime performance/resource benefit claimed. Removing the edge restores manifest/lock mismatch; changing owner code to avoid it would expand scope unnecessarily. Sibling subsumption is complete for semantics: the owning manifest already carries the dependency decision. Kill criterion would be a package/version/source change, altered production hashes or treating resolution success as executed verification. None appears in the reviewed amendment.

## Findings and verdict

- **KEEP / OBSERVATION:** reconcile the lock with its already selected owning manifest; prior architecture/source reasoning remains applicable.
- **REVERSE / OBSERVATION:** any claim that metadata or lock repair proves compilation/tests or actual archive trust.
- **DEFER / OBSERVATION:** native compilation/test execution to the coordinated owner window; no required architecture RESHAPE.

```text
VERDICT: APPROVE
Intent vs. shape: MATCHES — mechanical dependency resolution reconciliation.
User-value claim: SUPPORTED — removes stale lock obstacle.
Commitment status: HONORED — ownership and trust boundary unchanged.
Conceptual debt delta: PAYS DOWN — manifest/lock disagreement removed.
Sibling subsumption: FULL for dependency semantics.
Confidence: HIGH for static amendment; native execution unqualified.
```

Owner-reported execution lineage: initial granted attempt exited101 for a stale lock before compilation; process group85586 cleaned up; no retry in that window. Unfiltered offline metadata refused uncached nonhost js-sys without download; host-filtered aarch64-apple-darwin locked metadata exited0. These reports were supplied by root and not independently executed here. They establish neither a successful native build nor tests. Trellis retains the sole native window. Only this addendum added; all other files and owners' work preserved.
