# S3 bounded source closure

Captured upstream revision prefix `bc2f54bce075`, frozen within the M8 handoff. MIT copyright and permission retained verbatim in LICENSE. SOURCE-MANIFEST.json pins exact authorized frozen paths, source hashes and consumer hashes.

At capture, the entire callledger package (ledger, models, pricing, projection and package exports), provider model package and shared package initializer were copied byte for byte. Relative imports require no rewrite under gateway.shared.s3. The explicitly versioned consumer-local ledger delta below is the sole modification to that capture. The provider models include upstream shapes beyond M8; this adoption does not enable those wire features or any transport. No CLI, upstream tests, databases, runtime configuration or receipts are vendored.

Dependencies: Python 3.12, Pydantic 2 and the standard library. Upstream source documents SQLite initialization at explicit Ledger construction; no ledger is created by importing this package. Runtime stores/WAL must reside together outside OneDrive and repo/export roots. Consumer wrapper owns the mock-only eligibility gate and body-free projection.

Dirty Mode construction only: source digests and Python AST syntax inspected, no imports/application/database execution, no tests/builds/installs and no consumer conformance or provider evidence. External use remains disabled. Upstream authored tests/receipts are not independent M8 consumer evidence.


## Consumer delta M8-S3-CLOCK-1 (2026-10-25)

INT2 approved the exact local repair in PB-M8-R03 `I-D7-approve-S3-clock-r4.json`, plan SHA-256 `6cd26276f0373180766b3bfa04f68a32805119f20b2181e348f39b58bd416f0d`. Only `callledger/ledger.py` changes; upstream revision `bc2f54bce075`, LICENSE and SOURCE-MANIFEST.json remain unchanged. The manifest describes the captured upstream bytes, not this modified consumer file. No canonical owner source was accessed or changed.

Captured ledger SHA-256: `fefa367871c857d0bec3fb92f83647a4e86044296d9d221c68d57d27e36f34f1`.
Consumer ledger SHA-256: `afd8aa8b2cb42a57df93257a44f5bff57e4261c6fdb29b78e9cc042f04bc4dde`.

The original ledger compared raw wall time against a persisted effective time that could be advanced by its monotonic clock. A coarse unchanged wall tick could therefore cause a false rollback. Schema2 stores `last_wall` separately from effective `last_seen`. Funded calls reject true raw-wall regression; effective deadlines remain the maximum of wall time, process monotonic time and persisted effective time. Both high-water marks update under the existing IMMEDIATE transaction. Settlement may continue without lowering either mark. No tolerance, monetary reset, release or deadline extension is introduced.

The additive v1-to-v2 migration is atomic inside ledger initialization. It preserves existing authority, liability, halt, event and effective-clock data and seeds the missing raw-wall mark from legacy effective `last_seen`. This is deliberately conservative: historical raw time cannot be recovered, so a raw wall below that floor cannot fund until it catches up. Migration is limited to M8-owned disposable stores/test copies in this run. Unversioned existing authority tables, incompatible versions and invalid persisted UTC pairs fail closed. Old unmodified v1 code rejects version2; all workers on a store must use compatible code.

Executed local diagnostic evidence at this patch: RV1-authored ledger cases 7 passed, including the formerly failing coarse-clock case. Author migration diagnostics 5 passed: full-row financial/event preservation, old-code refusal, migration fault rollback, conservative legacy floor, real backwards wall before/after reopen, malformed-clock rejection. The first diagnostic run had one harness exception-class mismatch; its retained successor corrected the diagnostic catch, with no production change. Independent expanded controls/review and combined-tree acceptance remain pending. These results do not establish controller, live-provider, custody, Linux or full-product acceptance.
