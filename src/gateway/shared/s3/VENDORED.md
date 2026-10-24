# S3 bounded source closure

Captured upstream revision prefix `bc2f54bce075`, frozen within the M8 handoff. MIT copyright and permission retained verbatim in LICENSE. SOURCE-MANIFEST.json pins exact authorized frozen paths, source hashes and consumer hashes.

The entire callledger package (ledger, models, pricing, projection and package exports), provider model package and shared package initializer are copied byte for byte. Relative imports require no rewrite under gateway.shared.s3. No monetary semantics have been modified. The provider models include upstream shapes beyond M8; this adoption does not enable those wire features or any transport. No CLI, upstream tests, databases, runtime configuration or receipts are vendored.

Dependencies: Python 3.12, Pydantic 2 and the standard library. Upstream source documents SQLite initialization at explicit Ledger construction; no ledger is created by importing this package. Runtime stores/WAL must reside together outside OneDrive and repo/export roots. Consumer wrapper owns the mock-only eligibility gate and body-free projection.

Dirty Mode construction only: source digests and Python AST syntax inspected, no imports/application/database execution, no tests/builds/installs and no consumer conformance or provider evidence. External use remains disabled. Upstream authored tests/receipts are not independent M8 consumer evidence.
