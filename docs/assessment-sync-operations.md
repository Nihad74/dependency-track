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

## Dispatch

The relay polls the outbox and target work on one instance at a time. In `ACTIVE` it dispatches both. In `WITHDRAW` it dispatches only targets with a refresh pending, so policy results and metrics catch up with withdrawn rows. In `CAPTURE` and `OFF` it dispatches nothing. A target whose run is deferred by the mode keeps its reconciliation pending and is dispatched again in `ACTIVE`.

| Key | Default | Meaning |
|---|---|---|
| `dt.assessment-sync.relay.poll-interval-ms` | `1000` | Delay between relay polls, and the first backoff step. |
| `dt.assessment-sync.relay.batch-size` | `50` | Outbox rows and target rows taken per poll. |
| `dt.assessment-sync.relay.max-backoff-ms` | `60000` | Longest delay before a row whose runs keep ending without progress is dispatched again. |
| `dt.assessment-sync.fanout.batch-size` | `100` | Targets listed per expansion page. |
| `dt.assessment-sync.reconcile.batch-size` | `200` | Findings reconciled per transaction. |
| `dt.assessment-sync.workflow.max-batches` | `50` | Batches per workflow run before it continues as new. |

## Replay

Pending outbox rows and target work rows are the replay record. A Dex run that fails does not delete them. The relay submits them again. Do not close replay by sequence id or by timestamp.

## Lag

Two gauges show how far synchronization is behind. Watch both. An un-suppression at the source stays invisible on the target until the target work finishes.

* `dt.assessment_sync.backlog.oldest_event_age_seconds` is the age of the oldest outbox row. It covers the time until the affected targets are listed.
* `dt.assessment_sync.backlog.oldest_work_age_seconds` is the time since the longest-waiting target last had no unfinished reconciliation or refresh. It covers the stage after the outbox row is gone. Under constant load a target may never become idle, so treat this value as an upper bound for the delay of a pending request.

A gauge whose database query fails reports `NaN` and logs a warning. Alert on `NaN` as well as on high values, because a failed query is not an empty backlog.

## Access control

With portfolio access control on, a source feeds a target only when every team that can access the target can also access the source. Access through a parent project counts. Changes to team mappings, project parents, and team deletion are recorded and reconcile the affected projects and their descendants.

Turning `access-management` / `acl.enabled` on or off queues a full pass for every target that has a marker. Expect a backlog spike. Watch the lag gauges until they drain.

## Repair

The maintenance task runs on `dt.assessment-sync.verify.cron` (default `0 3 * * *`, UTC). What it does depends on the mode: `CAPTURE` runs backfill, `ACTIVE` runs verification, and `WITHDRAW` runs withdrawal. Nothing starts when the mode changes; the next scheduled run picks up the new mode.

Verification rebuilds each project's embedding index, compares findings with the same match, consensus, and diff as reconciliation, and enqueues a full target pass when the stored projection differs. It does not promote a row to `INHERITED` and it does not reset local ownership. An analysis with no origin stays protected.

Source events are the normal update path. Drift that appears on every verification means a writer is not recording changes. Fix that writer.

Run verification again after a replay, an algorithm change, or recovery.

## Withdrawal

1. Set `WITHDRAW`. New inheritance stops. Reconciliation must not create inherited rows in this mode. Withdrawal itself starts with the next scheduled maintenance run.
2. Maintenance selects analyses whose origin is `INHERITED` and resets those machine fields to neutral. `LOCAL`, `POLICY`, and `NEUTRAL` rows are not selected. Comments in `ANALYSISCOMMENT` stay. Every copied source trail on the project is removed, including source text kept as provenance on `LOCAL` rows. Affected projects get a refresh request, which the relay dispatches in this mode.
3. Read `dt.assessment_sync.inherited` and `dt.assessment_sync.rollback.incomplete`.
4. Set `OFF` only after inherited rows are gone and verification has been reviewed.
5. Turning the feature back on after a period with no capture requires backfill and verification again. `CAPTURE` pauses application. It is not withdrawal.

No load numbers are published here. This note does not state a sync deadline, a portfolio size, or a latency budget.
