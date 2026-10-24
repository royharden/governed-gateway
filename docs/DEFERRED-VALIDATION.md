# Deferred validation and activation handoff

Dirty Mode is OPEN for M8 source construction. **Nothing below was executed.** No installs, tests, builds, application/DB/crypto operations, provider calls, keys, services, containers, or listeners were used. Static source/digest/AST/JSON observations are not runtime or independent product acceptance. Closing Dirty Mode restores normal validation rules; it does not authorize live spend or publication.

## First activation sequence

1. Pin the actual candidate commit, OS/hardware/Python, source manifests, and relevant review dispositions. Provision only an approved existing local nonsynced runtime directory. Keep SQLite main/WAL/SHM together and use supported consistent backup/restore; never treat a copied live main file alone as a backup.
2. Resolve and review `uv lock`, then `uv sync --frozen`. Confirm declared Python/Pydantic/cryptography and package/import compatibility. The current source phase deliberately generated no lock and no test suite. Add the meaningful consumer/journey/security cases below before running test commands; an empty suite is not a pass. Declare/install appropriate development tools only in the authorized activation phase, then run relevant Ruff/type checks and pytest against real cases.
3. Follow `docs/bootstrap.md` with a matching fixed nonsecret config, `GATEWAY_RUNTIME_ROOT`, and fresh stores. Run `uv run python -m gateway.bootstrap --config <absolute-config> --initialize`. The example is synthetic and expires; do not renew an existing authority, cap, quota, key identity, or deadline to make a run succeed. Missing halves/changed stores must fail closed. The memory-only CLI recipe makes no cross-process restart or persistent-key recovery claim.
4. Exercise actual evaluated mock genesis, request, duplicate replay, budget rejection, shadow disagreement, exact activation/stale CAS/rollback, and report artifacts. Verify every acquisition uses the same monetary/stop/claim boundary. Reproduce actual outcomes; do not substitute modelled sample arithmetic or a prewritten passing report.
5. Establish a separately authorized persistent runtime trust/key setup before claiming restart/ciphertext recovery: operator-private/runtime-public signing split, distinct replay/client secrets, Windows/Linux ACL read/write denial, wrong-key/tamper/domain/source/OS-account tests, and key rotation/migration. Real Windows protected-file key loading is intentionally fail-closed until an actual trusted loader is configured and verified. No real-key request until Roy starts the live phase.

## Mandatory deterministic safety cases

All A01-A16 conditions require actual consumer and controller execution, independent integer micro-USD oracle checks, and a transport spy. Failures remain in reports. Required accounting equations are `R+X=F+A+L+K+U` and exposure `K+F+A+U+D`; X is already included in K. Late evidence never reduces U or a previously recorded maximum D.

| Case | Later executable validation |
|---|---|
| A01 budget race | Near-empty authority with simultaneous contenders; affordable whole graphs only, no negative headroom or unfunded send |
| A02 duplicates | Same/different-body key races, lost reply, replay TTL/tombstones; one claimant, 202/409/410 and original retained result correctly distinguished |
| A03 crash boundaries | Kill owned workers separately after permit, funding, claim, handoff, stage, settlement and terminal commits; no reconstructed ticket or lease refund; prove conservative recovery |
| A04 faults | Timeout/disconnect/cancel/429/503/malformed or absent usage; full unknown exposure; retry only separately declared/funded child with actual proof |
| A05 settlement conflicts | Identical settlement no-op; conflicting evidence retained and halting, no second debit or refund |
| A06 invalid bounds | Direct/late above-bound charge unclamped, no double X/D debit; stale/missing price/bound evidence, clock rollback, count-call proof failures halt/reject |
| A07 authority continuity | Reopen with changed run/date/policy/config/deadline/cap/quota; same immutable authority persists or incompatible reopen refuses, never resets |
| A08 durable failures | Disk-full/schema/corruption/truncated JSONL; authoritative store protected, projection rebuild and durable-write failure fail closed |
| A09 wire subset | At least20 normalization vectors per provider profile and25 explicit unsupported cases; raw64KiB/32-message/output-cap/UTF8/duplicateJSON/header/role/type constraints; no funding/dispatch on invalid input |
| A10 activation | Competing generation CAS, changed bundle/report/corpus/profile/price/bounds, stale/rejected/revoked decisions; at most one eligible exact-tuple activation |
| A11 authority separation | Client/actor spoof, wrong signing key/domain/tampered tuple, runtime-write denial, custom endpoint refusal; safe errors and no bodies/secrets in logs/ledger |
| A12 shadow | Identical serving route/attempts with shadow on/off; no transport/ledger capability in candidate recommendation; unobserved counterfactual explicit |
| A13 rollback | New permits use eligible rollback; old bounded permits retain original identities; stale/expired/revoked/incompatible target refuses, no emergency freshness waiver |
| A14 emergency stop | Shared lock linearizes stop versus funding/claim/handoff/retry; already handed-off work remains accounted, stop survives restart |
| A15 evaluated genesis | Empty serving store rejects; explicit signed bounded evaluation can run without active policy through same ledger; mock evidence cannot authorize external serving |
| A16 replay/privacy | AEAD binding/nonce/result digest/wrong-key/rotation/reopen; stage before settlement/ack; fixed terminal24h expiry; unknown/abandoned ciphertext purge preserves tombstone/receipt/U/D; unknown409 precedes expired410 |

Run at least100 reproducible generated/barrier schedules per supported Windows/Linux run, covering1,2,8 processes and every named deterministic crash boundary. Record actual distribution/seeds/interleavings. Require sends <= unique consumed tickets; equality applies only without a crash/cancel between claim and handoff. Lost committed tickets can conservatively have no send. Test only isolated temporary authorities/stores, never another project's DB/containers.

Exercise direct pinned S3 consumer calls and full API/controller path. Validate the independent integer oracle against hand-calculated positives and deliberately mutated negatives before using it to judge production. The custodian must not independently certify its own oracle. Test max-attempt1 and2, peak/unused/released retry holds and counterfactual single-attempt admission; no claim of implemented lazy funding. Measure actual p50/p95 stage/combined overhead versus direct adapter with identical delays/hardware and sample counts.

## Specific source-repair regressions

- Exact Decimal-context-independent conservation/excess/quote math, including large integer amounts plus one micro-USD, negative paired intervals and source-preserving canonical hash/signature roundtrips.
- Complete configuration/lifetime/price/bound registry binding on reopen, canonical duration strings, original request witness registration and ledger-only projections without recursive policy transactions.
- Only scripted synthetic proven-not-sent fault has complete0 usage; unproved/ambiguous/missing billing remains unknown. Verify actual pinned priceknown0, real S3 settlement, guarded trusted retry source, persisted readiness and distinct prefunded new child. Do not infer real provider no-charge rules from mock fixtures.
- Stage/reopen per-attempt nonce/ciphertext/result/AAD/binding/receipt metadata, fixed public terminal TTL overlay and terminal unknown/abandoned pruning; active staged-known recovery data preserved.
- Correct closed AdapterError mapping at pre-funding and post-claim boundaries; no unsafe-latch poisoning for ordinary input/profile errors, no refund/reclaimed ticket after a consumed claim; original cancellation exception survives cleanup failure.
- Bounded/deduplicated simulation journal across repeated idempotent replies, conflicting observations and overflow; preserved diagnostics and ineligibility, no silently dropped facts or cleared failure latch.
- Full immutable observed-artifact bytes/hash/count/domain/candidate/evaluator/scoring-authorization/receipt coverage and exact manifest binding. Test altered/reused/static-acquisition facts and report bundles, not just a hash/count. No plaintext in diagnostic/operational evidence.
- Non200 known0/nonzero charges and partial known K with F/A/U/D; actual per-operation totals distinct from authority totals. Unknown/unreadable is not invented zero. Diagnostics and public JSON/Markdown retain honest partial/scoped financial facts and assigned denominators.
- Explicit CLI configuration, fixed authority lifetime and quote-driven cumulative permissions versus actual single-ledger ceiling. Permission maxima are not additional wallets. Test source sample assumptions rather than adjusting cap or outcomes after spending.

## Evaluation, live gates and acceptance

Development is60 synthetic tasks20 per extraction/evidence-QA/transformation family. These are public development fixtures, not independent holdout. Later appoint a nonauthoring custodian with enforced read-denial storage, freeze methods/templates/policy/baseline before creating >=120 fresh holdout tasks40/family, and appoint a separate nonauthoring reviewer outside product/custodian lineage to audit oracle/corpus/harness and the exact product commit.

Execute B0/B1/C plus separately labelled S3-style offline replay with exact request/model/parameter/profile/adapter/price provenance. Keep missing/error/refusal/timeout in assigned denominators; report observed versus assigned estimates, unknown costs/liability and unavailable cost-per-success when no successes. Report Wilson95 and preregistered task-paired10000-resample intervals; per-family tolerance0.05, limited power and inconclusive findings keep the baseline. Actual authority evidence, compatibility, statistical classification and measured benefit are separate. Original acquisition/current reuse costs and actual calls/attempts must remain visible.

Live work is NOT authorized. Before any live activation: implement real direct OpenAI/Anthropic transports with retries/redirects disabled and the exact supported subset; pin current primary model/API/capability/price/all-billed conservative request bounds and no-charge/count evidence; obtain actual disclosure/custody/cost authority. No custom/local base URLs. No key requests until Roy explicitly starts that phase. The adopted future aggregate ceiling isUSD30, tranches1development/24acceptance/5reserve; reserve release is a separate decision, not a refund/reset.

A concrete full campaign quote must include >=240 paired holdout generations +20 smoke tasks (10/provider), controlled failures, development/count/retry/judge components if any, expected cost AND sum of conservative maxima/unknown sensitivity. Require `130*(bA+bB)+extras<=24` for the acceptance tranche. Current loose full-context feasibility is insufficient; do not shrink120 tasks or present mocks as live evidence. Inability to fund/obtain proof remains incomplete.

Full product acceptance requires the separate nonauthoring reviewer, actual executions/receipts, exact scope/candidate/environment/corpus bindings, per-requirement pass/fail/incomplete and disclosure of all failures. Static package reviews, source agreements, hashes, and developer-owned simulation observations do not replace that acceptance. Publication, push/deploy, cloud/accounts and any live spend remain separate actual authorization.

## Current operating boundary

Role relevance and the clean-room operating rule were adopted via delegated decision on2026-10-24; Roy has not personally signed the blank line, and this is not legal clearance. No SeniorSocial nonpublic material may be accessed/copied/translated/used; exposure/contamination requires isolation and written resolution. Provenance is recorded per dependency/fixture. M9 has priority, current M8 five-DL source staffing is unchanged. Existing other-project stacks/processes remain untouched.
