# Assessment synchronization operations

The mode is cluster-wide configuration. Stop feature dispatch and let in-flight batches finish before every instance changes mode together. Changing one process does not change the cluster.

`OFF` is not a finished rollback while `dt.assessment_sync.rollback.incomplete` is 1. That gauge is 1 when the mode is `OFF` and any analysis origin is still `INHERITED`.

The maintenance scan cursor is the last finished project UUID. Dex stores it in the workflow's continue-as-new argument. The next batch reads `UUID` values greater than that cursor, ordered by `UUID`, in a bounded page. It does not use a maximum row id or a wall-clock watermark. A project created or changed behind the cursor is covered by its captured outbox event. Do not delete pending outbox rows to make a scan look finished.

## Backfill

1. Deploy with `dt.assessment-sync.mode=OFF`. Drain writers that do not record the outbox.
2. Set `CAPTURE`. Authored changes are recorded. Inheritance is not applied.
3. The maintenance task backfills origin rows and embedding indexes. A row with no origin is labeled `LOCAL`, or `POLICY` when it already has a vulnerability policy. The decision text is not replaced.
4. Leave the outbox in place. Events recorded during the scan are still pending after the scan.
5. Set `ACTIVE`. Let expansion and target work drain.

## Replay

Pending outbox rows and target work rows are the replay record. A Dex run that fails does not delete them. The relay submits them again. Do not close replay by sequence id or by timestamp.

## Repair

Verification runs on `dt.assessment-sync.verify.cron` (default `0 3 * * *`, UTC). It rebuilds each project's embedding index, compares findings with the same match, consensus, and diff as reconciliation, and enqueues a full target pass when the stored projection differs. It does not promote a row to `INHERITED` and it does not reset local ownership. An analysis with no origin stays protected.

Source events are the normal update path. Drift that appears on every verification means a writer is not recording changes. Fix that writer.

Run verification again after a replay, an algorithm change, or recovery.

## Withdrawal

1. Set `WITHDRAW`. New inheritance stops. Reconciliation must not create inherited rows in this mode.
2. Maintenance selects analyses whose origin is `INHERITED` and resets those machine fields to neutral. `LOCAL`, `POLICY`, and `NEUTRAL` rows are not selected. Comments in `ANALYSISCOMMENT` stay. Copied source trails for the withdrawn rows are removed. Affected projects get a refresh request.
3. Read `dt.assessment_sync.inherited` and `dt.assessment_sync.rollback.incomplete`.
4. Set `OFF` only after inherited rows are gone and verification has been reviewed.
5. Turning the feature back on after a period with no capture requires backfill and verification again. `CAPTURE` pauses application. It is not withdrawal.

No load numbers are published here. This note does not state a sync deadline, a portfolio size, or a latency budget.
