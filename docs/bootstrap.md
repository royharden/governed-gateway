# Explicit no-key simulation bootstrap

## Reproducing the local environment

The R03 environment pins CPython 3.12.13 in `.python-version`, runtime and development
dependencies in `uv.lock`, and setuptools 80.9.0 as the build backend. From any
directory, use `uv sync --project <absolute-checkout> --frozen --python 3.12.13`.
Then use `<checkout>/.venv/Scripts/python.exe` on Windows. An editable installation
loads that checkout's source; when borrowing an interpreter for another checkout,
set `PYTHONPATH` explicitly to that other checkout's `src` directory.

`uv build --project <absolute-checkout>` produces a source archive and wheel.
The wheel supports package imports; the demonstration currently requires the source
checkout's frozen development fixtures and migration. It is not a self-contained
installed-wheel demonstration.

On Windows, `scripts/bootstrap.ps1 -Config <absolute-nonsecret-json> -RuntimeRoot
<absolute-existing-local-directory> -Initialize` invokes the local interpreter and
temporarily sets `GATEWAY_RUNTIME_ROOT`. It does not create or renew a configuration,
change its budget, load credentials, or enable external transports. Obtain an explicit
new simulation authority before creating fresh stores. An expired sample remains
expired; preserve its fixed lifetime and retained stores.

The historical construction notes below describe the original unexecuted source
baseline. R03 dependency sync, package import, bootstrap `--help`, and archive/wheel
build have executed on Windows with Python 3.12.13. These checks do not establish
the full journey, restart, custody, live-provider, or product acceptance obligations.

The process-local high-water implementation keeps one private SQLite connection
for the context lifetime. Each clock invocation still validates the full runtime
path, checks the pinned database identity and authority configuration, reads durable
time, checks rollback/drift, and commits its compare-and-swap under the authority
lock. It never reuses an observed time between calls. Recursive observations refuse;
threads serialize through the same lock. Forked, closed, replaced-path, or failed
handles refuse rather than reconnect. Closing the context also closes this handle;
bootstrap failures attempt both ledger and high-water cleanup. These lifecycle
rules require the independent clock/path/storage checks before acceptance.

This is source construction, not a verified runnable demo or runtime/product acceptance. No bootstrap, database, signing, acquisition, installation or test was executed while authoring it. Real provider APIs and protected-file key loaders are not wired here.

The intended entrypoint is `python -m gateway.bootstrap --config <absolute-nonsecret-simulation.json> --initialize`, from an installed package or a separately configured src-layout Python environment. It builds concrete trusted services and calls the actual packaged `gateway.cli.demo.main(services=...)`. Calling `gateway.cli.demo.main()` without injected services still fails closed; it does not implicitly bootstrap or load a dotenv file.

The operator must first provide an existing local nonsynced runtime directory and copy the nonsecret configuration into that directory. `GATEWAY_RUNTIME_ROOT` must explicitly name that same directory. No folder provisioning, package installation, environment mutation, or listener is performed by this recipe. Windows fixed drives and supported local Linux filesystems use the shared locality rules. Repository, OneDrive, export, symlink/reparse and unknown/network locations refuse.

`fixtures/bootstrap/simulation.example.json` is reviewable synthetic input with a fixed explicit authority lifetime ending **2026-10-26T00:00:00Z**. It expires and then must be refused. Its paths must match the operator's actual machine. Preparing a separately approved new fresh authority requires explicitly choosing its ID, created/deadline times, cap and quota; no current-date fallback, daily reset or automatic extension exists. The example's price schedule is invented simulation data, not provider prices or permission to spend.

The narrow JSON recipe refuses duplicate and unknown fields. It supplies permanent authority/lifetime/cap/quota, two synthetic price rows, the existing frozen 60-task development directory, explicit baseline/candidate routing, cumulative evaluation authorization maxima, clock bounds and the two request bodies. Prices, model/profile manifests, source-code identities, metric/feature identities, evaluation spec and policy hashes are computed from their actual declared nonsecret content and current frozen source; no placeholder hash, passing evaluation, approval or active policy is accepted as input. Tasks/labels are validated by the packaged development loader. Labels go only to scoring and never become mock responses.

The loader derives four immutable bundles: baseline serving (two prefunded attempts and a declared large-output boundary route), candidate serving (two prefunded attempts), and two single-attempt static acquisition bundles. They share the same frozen method/price/profile dependencies. The baseline rule sends requests above512 output tokens to B1; development tasks128 and the original request128 use B0. Configured static acquisitions run both B0 and B1 through signed bounded controller evaluation, without an active serving policy. Serving and both evaluations share one permanent authority and ledger.

The example models USD0.004500 of **synthetic** cap and256 attempts. With the current constant mock usage (8 input tokens,4 output tokens), the declared zero input rates and output rates1/2 USD per million produce4/8 micro-USD per actual B0/B1 mock attempt. One 60-task/two-target evaluation would therefore acquire120 attempts costing720 micro-USD. The original B0 request would cost4 micro-USD. Profile maximum output1024 makes a B0 child reserve1024 micro-USD and B1 reserve2048; the two-child original plan reserves2048 and the boundary B1 plan4096. After the modeled first evaluation/original cost724, boundary exposure would be4820, above the4500 cap; candidate acquisition single-child maxima remain below the same cap through the modeled final1444 known cost. These are arithmetic assumptions from current source, not observed results, a proof of actual execution, or a reason to change the cap after spending. Adapter/ledger/gate timing, real source behavior and runtime feasibility remain unverified; any mismatch must fail or be reported honestly.

Governance also charges the **original maximum of every nonabandoned permit cumulatively per signed evaluation authorization**, even after settlement releases a reservation. USD0.004500 cannot serve as that 120-acquisition work limit. The example therefore explicitly declares and signs distinct cumulative worst bounds, checked before signing against actual guarded ACCOUNT.reserve_for quotes for every declared task/target/attempt count:

| Signed policy scope | Declared full-plan calculation | Cumulative authorization maximum |
|---|---|---|
| acquire-B0, shared across both evaluations | 2 phases ×60 tasks ×1 child ×1024 micro-USD | USD0.122880 |
| acquire-B1, shared across both evaluations | 2 phases ×60 tasks ×1 child ×2048 micro-USD | USD0.245760 |
| baseline scoring policy | 60 potential candidate plans ×2 children ×1024 micro-USD | USD0.122880 |
| candidate scoring policy | 60 potential candidate plans ×2 children ×2048 micro-USD | USD0.245760 |

The scoring authorizations have bounded potential candidate plans; C scoring in this recipe reproduces selectors over the static outcome tables and makes no extra acquisitions. The actual two-phase static acquisition sum of original plan maxima is USD0.368640. All four signed permission maxima sum to USD0.737280; they are scoped work limits, **not additional wallets, funds or headroom**. Every authorization has the same actual authority ID/budget reference and immutable lifetime. Cached static authorization IDs/maxima persist across both phases and cannot reset their cumulative counters. The one ledger still limits actual K+F+A+U+D to USD0.004500, independently of those cumulative limits. A campaign can be rejected if actual bounds/unknown charges consume that financial capacity; successful release under a mock outcome is an assumption, not guaranteed funding for every future task.

This intentionally narrow simulation configuration does not establish live whole-campaign affordability, real billing bounds or the future `130*(bA+bB)+extras <=24` feasibility condition. External mode remains disabled. No financial cap, authorization gate or admitted history is weakened or reset to make the example pass.

Future invocation creates ephemeral simulation signing/replay/idempotency/client-secret identities only in memory. No real credential file is read and no token/private key is printed. They are deliberately not a restart/key-rotation implementation: a second CLI process with fresh ephemeral identities must reject existing stores rather than replace authority/configuration, rotate unreadable replay state, delete files or reset funds. Keep historical DBs for investigation. The explicit initialize flag only permits an absent matching local store pair; a missing half or changed identity is an error. This recipe makes no existing-store recovery/key-custody claim.

The actual future async demo evaluates and scores before signing, then performs approved activation, request/replay, budget boundary, zero-call shadow and eligible rollback/CAS checks through existing producers. Constant mock text can measure zero task quality; compatibility and unmeasured benefit remain separate. Failed or missing outcomes keep their actual known charges, partial charges and unresolved liability in body-free observation evidence; no fake pass is substituted. The observation journal is bounded/deduplicated and is developer evidence, not an independent oracle, biological-human act, custody or complete A01-A16 acceptance.

Before claiming the journey works, separately authorize and execute import/package, local filesystem/ACL, crypto, SQLite/WAL/locking/clock, producer integration, evaluation/receipt/artifact/failure, replay/stop/recovery and selected acceptance validation. The example and command are a concrete source integration path, not an execution receipt.
