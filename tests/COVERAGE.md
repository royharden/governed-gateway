# Public reviewer checks

RV1 authors these checks against the selected M8 plan, M8-CONTRACTS and
M8-EVALUATION. They use public synthetic fixtures only. They are not hidden-corpus
custody, live-provider evidence, or final product acceptance. RV2 independently
reviews this contribution. Production repairs belong to assigned DLs.

Use Python 3.12.13 and the exact installed versions in
`requirements-win-py312.txt` for this Windows baseline. D6 owns the authoritative
project dependency lock. `scripts/check.py --source-root <exact-checkout>` prints
the selected source and test commit identities and runs against that source,
including subprocess CLI execution. Record dirty status separately: a HEAD alone
does not prove unchanged source. `--junit <outside-repo-path>` writes test results.
No installer, credential loader, provider request or server starts in this runner.

All runtime artifacts are preserved beneath a unique directory in
`C:/agent-runtime/m8-rv1` on Windows, `/tmp/m8-rv1` on Linux, or an explicitly chosen
`M8_TEST_ARTIFACT_ROOT`. Tests never renew existing authorities. Each CLI case
declares a new synthetic ID/lifetime and retains the sample's cap, quota, prices
and public task count. Ephemeral crypto bytes are in memory only. Do not interpret
these new isolated test authorities as renewal of any accepted financial history.

| Requirement | Executable scope | Remaining evidence |
|---|---|---|
| A01 | Direct S3 whole-graph refusal and 100 barrier admission schedules: 34 at 1 process, 33 at 2, 33 at 8 | Full controller sends/tickets matrix; Linux execution |
| A02 | CLI journey asserts retained duplicate with no extra dispatch; consumer rejects second claim | Simultaneous same/different-body races; lost response; TTL/tombstone controller matrix |
| A03 | Real ledger reopen preserves known/unknown state and spent ticket | Forced process death at every named commit boundary; staged recovery |
| A04 | Provider normalization preserves missing/invalid/unknown billing; consumer unknown keeps full hold | Controller timeout/cancellation/retry/stop integration |
| A05 | Identical direct settlement no-op; changed settlement rejected | Concurrent late-evidence journal/incident assertions |
| A06 | Integer hand cases, unclamped excess, halted direct ledger; coarse-clock regression | Count-call proofs; persistent late incident and actual wall-clock precision repair |
| A07 | Changed authority cap refused; known/unknown reopen retained | Cross-run/date/policy adversarial controller matrix |
| A08 | SQLite actually executes with preserved artifacts | Corruption/disk-full/projection interruption/fault injection |
| A09 | 26 unsupported bodies through parser and ASGI with zero controller calls; 20 normalization vectors per profile plus billing/finish cases | Full controller funding/transport spy proof for all invalid boundaries |
| A10 | CLI activation/stale CAS/rollback journey | Competing operators and all exact-tuple mutation cases (RV2 shared/governance scope) |
| A11 | Invalid/duplicate headers fail before controller; external synthetic evidence refused | Signing/ACL separation and persistent runtime trust |
| A12 | CLI checks advisory disagreement without extra dispatch | Independent shadow-on/off controller spy equivalence |
| A13 | CLI eligible rollback and unchanged funds | Expired/revoked/stale rollback and active permits |
| A14 | Not covered by this batch | Stop/claim race, restart-stopped proof |
| A15 | CLI actual evaluated genesis, no seeded passing report | Empty-store serving refusal and full external-mode denial matrix |
| A16 | AEAD nonce uniqueness, all binding fields, wrong key, ciphertext tamper | Staged result recovery/TTL/purge/rotation/reopen/ACL |

The integer oracle contains no production accounting imports. Hand-computed
positive examples and deliberately broken conservation states validate its limited
arithmetic model before comparison with production projections. It is not the
separately appointed custodian's protected event-stream oracle.

Admission schedules synchronize all open worker ledgers at a barrier. Seed chooses
affordable capacity and 1/2-child graph. The test does not claim deterministic OS
interleaving replay. Fixed UTC and zero monotonic clocks isolate admission from a
separately failing coarse-clock regression; record that limitation. These schedules
fund plans and perform zero dispatches. They do not satisfy the full crash/retry/
controller schedule requirement. `schedules.json` records actual seeds, outcomes,
clock assumption and totals after every executed schedule. Failure remains in the
test result; no xfail or silent floor reduction is used.

The LedgerAdapter consumer case executes the actual M8 wrapper, SQLite ledger and
OS lock with an explicit authorization gate double and a supported fixed monotonic
ledger seam. It checks refusal/funding/idempotency/claim/unknown/reopen behavior,
not governance correctness. The CLI case executes real composed producers and
must fail until shared schema/runtime defects are fixed. Pydantic tuple and clock
failures are never converted to a pass by changing expected outcomes.

All newly authored wire/clock/crypto tests are synthetic regression fixtures. No
SeniorSocial source, prompts, tests, data or credentials were accessed or copied.
Dependency provenance is the existing MIT S3 closure, declared product packages
and pinned pytest dependencies from public package indexes.
