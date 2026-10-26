# M8 public development and SQLite check

Independent RV2 checks use only the committed synthetic 60-task development set.
Correct-answer receipt fixtures test scoring plumbing; they do not measure model
quality. Complete synthetic answers without authority evidence cannot pass.
The actual controller journey uses the existing constant mock responses and may
score zero quality. No hidden case, holdout, API key, real provider or spend runs.

Build the root Dockerfile from the exact candidate checkout. Its Python base is
pinned by digest and dependencies by exact versions. COPY is an explicit allowlist.
Run agent-ports claim/check for `m8/r03-rv2` before creating resources. Create a
new named volume and container, both `m8-r03-*`, with labels
`agentports.project=m8`, `agentports.instance=r03-rv2`, `agentports.owner=0064`.
Mount the volume at `/m8-runtime`, use `--network none`, `--read-only`,
`--cap-drop ALL`, `--security-opt no-new-privileges`, and publish no port.
Temporary test capture files use that writable owned volume via `TMPDIR`.
The ledger reserves 22500 but this batch starts no listener.

The runner preserves its fresh explicit synthetic authority config, SQLite
stores, failed/passed pytest logs, evaluation artifacts and docker-result.json in
the volume. It does not remove containers, volumes, files or databases. A new run
uses a fresh subdirectory, cap USD0.004500 and attempt quota256; no existing
authority is extended or reset. Original expired sample remains unchanged.

Runtime SQLite locality rejects overlay/tmpfs; the named volume must resolve to
an admitted local ext4/xfs/btrfs mount. A refusal is a real failed check, not grounds
to monkeypatch the locality gate. Preserve resources for review. This packaged
journey is bounded mock evidence, not full A01-A16/100-schedule or product acceptance.
