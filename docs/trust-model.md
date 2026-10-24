# Local governance trust model

Construction status: source only, runtime unverified. External dispatch is
disabled. This document describes the selected boundaries; it does not establish
that SQLite durability, signatures, permissions, monetary admission or the joined
request path have passed execution checks.

## Operator, runtime and client

The local operator CLI holds the approval signing capability. It displays the
exact candidate and evaluation tuple, observes the local OS account, and requires
an explicit decision and reason. A caller-provided actor name is not identity.
The client API token cannot approve, evaluate, activate, revoke or sign policies.

The gateway receives an Ed25519 verification public key through trusted local
configuration. Its governance module exposes no signing function or private-key
loader. A signature authenticates key possession and the exact canonical bytes;
it does not prove a biological human pressed a key. A process running as the
operator or a host administrator may have access to signing keys. This is a
single trusted-host boundary, without organizational separation-of-duties or
protection from a compromised administrator.

Shared schemas own strict records and canonical signed-payload encoding. The
operator and runtime must use the same versioned helper: UTF-8 JSON with sorted
keys, no whitespace, no nonfinite values, explicit nulls/schema versions and
normalized decimal strings. User text is not normalized. Evaluation authorization
and policy approval use distinct signature domains. The signature is excluded
from its signed payload; the stored-record digest includes the signature.
Neither a model response nor a client credential can manufacture authority.

## Evaluated activation

An empty store has no active policy. Requests fail closed until a frozen baseline
has a separately authorized evaluation, frozen eligible evidence and an exact
signed approval. Evaluation authorization carries a finite budget reference and
does not waive ledger funding, unique attempt claims or stop checks. A simulation
approval authorizes simulation only. Fixture files cannot stand in for executed
evaluation or create a preapproved genesis.

The immutable tuple binds the bundle, evaluation, artifact manifest, evaluation
specification, evaluator code, corpus, matching rules, adapter/capability, bound
and price snapshots. A changed tuple requires new evaluation and approval.
Eligibility checks current evidence validity and an explicit positive evaluation
maximum age. Missing evidence, unknown clock trust and stale data fail closed.
The simulation specification uses a declared 24-hour maximum age; this is not a
live-provider freshness proof.

Activation checks the exact approval and current nonrevocation, compares the
expected generation and appends a new generation in one policy-store transaction.
Only one contender may win that comparison. Rollback is another activation of a
still eligible approved tuple and always records a new generation. It has no
freshness, revocation or emergency waiver. Reject and revoke history is retained.
No eligible policy means no new serving admissions.

## Policy and ledger authorities

The policy store owns immutable bundles, signed decisions, evaluation references,
generation history and bounded operation permits. The ledger owns funding,
attempts and settlement. They are separate durable authorities. No distributed
transaction or exactly-once network guarantee is claimed.

The policy transaction pins the generation and complete immutable permit. A
separate ledger transaction funds the entire declared attempt graph. A dual-store
join must compare committed authority, operation, permit, request, policy,
serialized envelope, adapter/capability, price and bound identities. A supplied
`LedgerJoin` record alone is not proof: the accounting/controller seam must read
the actual committed ledger state. A funded marker in the policy database cannot
authorize sending by itself.

Only the successful fresh ledger `begin_attempt` return is a send ticket. Each
child has one allowed attempt. A lost return, ambiguous dispatch or restart never
reconstructs that ticket or replays the network send. A separately declared retry
is a distinct prefunded child and requires its pinned no-charge/pre-send evidence.
There is no automatic retry after an ambiguous timeout or disconnect.

Controller, accounting, governance and recovery share one reentrant local
cross-process authority lock. The controller holds it across stop inspection,
ledger claim and handoff to transport, then releases it before waiting for the
response. Stop changes acquire that same lock. Already handed-off work may finish;
no later handoff may win after stop commits. The lock is not another durable claim
store. Lock failure prevents dispatch. This linearization is unverified until the
joined Windows/Linux concurrency and crash cases run.

Changing the active generation affects new permits. Existing requests retain
their bounded pinned identity and expiry. They still pass pre-attempt stop,
incident, deadline and bound-evidence checks. Recovery abandons an unfunded permit
only with verified ledger absence under the shared lock. Future holds close only
with ledger-checked undispatched proof. Active ambiguous work keeps its liability;
a lease or timeout alone is not proof that an upstream was free.

## Incidents, stop and clock

Emergency stop persists across restart. An incident halt is irreversible in this
MVP: there is no clear-incident, write-off, reset or liability-release API.
Settlement may remain available where the ledger permits even when spending is
halted. Credible higher conflicting settlement evidence must not disappear merely
because the ledger rejected a second settlement.

Late evidence never changes immutable terminal unknown liability `U`. Identical
scoped evidence is a no-op; conflicts stay visible. Keep the maximum credible late
charge and `D = max(C_late - U, 0)` without reducing either on a lower observation.
Report `K + F + A + U + D`; known excess `X` is already included in `K` and is not
added again. Unauthenticated evidence is quarantined and halts. Evidence,
monotone maxima and halt must commit together. Interrupted projection of a ledger
breach must recover a fail-closed halt before funding or dispatch resumes.

Clock rollback or unknown freshness prevents new spending. The trusted local
clock needs persistent high-water and process monotonic/wall consistency checks;
an arbitrary supplied UTC timestamp is insufficient. Clock or expiry never
refunds unresolved liabilities. A new run, policy, worker or calendar date cannot
reset the finite authority.

## Local storage and privacy

Runtime SQLite databases, WAL and companion files reside together on a local,
nonsynced disk outside OneDrive. INT owns versioned migrations. Governance opens
only a compatible pre-migrated authority and refuses incompatible schema or
authority configuration. Database/write failures cannot create an admission.
Backups use SQLite's supported consistent procedure; copying only a live main
database file is not a recovery plan. No runtime database is created during the
source-only construction phase.

The policy/ledger journals contain safe opaque IDs, digests and accounting fields,
not prompts, provider exception strings or response bodies. The controller/replay
owner stages only normalized replay results encrypted with established AES-GCM
under a separate OS-protected runtime key, associated with operation/request/policy
identities. Successful replay requires matching durable settlement and terminal
policy state. Missing or mismatched ciphertext never triggers another provider
call. The default retention is 24 hours; permanent idempotency tombstones outlive
ciphertext. Database copies without the key must not disclose result text.

Signing, encryption, client and provider secrets are separate. Actual keys live
outside repository/export roots in OS-protected runtime locations, referenced by
environment variable names. They are never command-line values, fixtures, logs,
reports or committed environment files. ACL enforcement and runtime-write denial
remain deferred; hashes alone do not prevent administrator modification.

## Deferred validation

The later activation phase must verify schema compatibility, SQLite WAL/CAS and
crash recovery; exact canonical/signature vectors and tampering; wrong-key and
runtime-write denial; evaluated genesis; expiry/revocation/rollback races; trusted
clock behavior; shared-lock stop/claim/handoff ordering; committed ledger joins;
late/conflicting evidence and monotone halt; encrypted replay and tombstones.
Independent oracle/custody, held-out evaluation, S3 consumer conformance and real
two-provider bounds/receipts are separate unfinished acceptance obligations.
Source review does not establish any of those runtime results.

## Source composition and terminal expiry

The stage's encrypted GatewayResult may carry a provisional expiry because it is
written before settlement. The first matching terminal policy commit fixes one
terminal timestamp and its exact 24-hour expiry. First delivery and every replay
overlay that same persisted expiry after decryption, alongside the replay marker;
text, refusal, usage and cost remain the original result. Duplicates do not extend
retention. Unknown settlement has no successful replay or expiry.

Runtime binding is one-time trusted bootstrap: actual shared guard, root trusted
clock/context/composite-profile loaders, committed ACCOUNT operation reader and
registered incident source resolver. It occurs before first policy DB use. An
unbound callback cannot authorize admission. Retry additionally needs an actual
trusted adapter-normalization observation plus the committed known-zero original
settlement and prefunded conditional child. A client boolean or missing source
cannot stand in for that proof. A lost process-local proof after restart denies
retry and conservatively retains exposure until verified safe cleanup; it never
reconstructs a send ticket. Policy getters/operator projections are read-only and
scoped to the configured local authority; no public operator HTTP API is added.

Evaluation generation0 is a purpose sentinel, so a separately authorized candidate
can be evaluated after serving has an active generation. It does not select or
replace serving policy. The signed evaluation ceiling is conservatively charged
against the declared maxima of its nonabandoned permits, in addition to actual
ledger funding; changing an evaluation ID does not replenish the ledger authority.

Terminal-unknown ciphertext is unservable and is cleared in the same transaction
that records unknown terminal state. All attempt-stage bodies are cleared;
receipts, digests, permanent tombstones, joins and immutable unknown liability
remain. The bounded cleanup command also clears any old unknown-terminal bodies
without giving them a replay TTL or relabeling them as successful/expired known
results. No cleanup or database command has been executed during construction.

Abandoned or proven all-unstarted operations likewise clear any leftover staged
ciphertext atomically with their terminal projection. Bounded cleanup includes
legacy abandoned leftovers while preserving their tombstones and evidence. It
does not select active or staged-known results awaiting settlement/recovery under
this terminal-only cleanup rule.
