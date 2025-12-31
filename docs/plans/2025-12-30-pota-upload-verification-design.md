# POTA Upload Verification Design

## Problem

Currently, POTA uploads are marked as "uploaded" when HTTP 200 is returned, meaning the file was accepted for processing. But POTA processes files asynchronously - actual success requires checking job status via the `/user/jobs` API.

## Solution

Add immediate polling after upload + background verification fallback.

## Schema Changes

Add columns to `pota_upload_status`:

```sql
ALTER TABLE pota_upload_status ADD COLUMN job_id INTEGER;
ALTER TABLE pota_upload_status ADD COLUMN verified_inserted INTEGER;
ALTER TABLE pota_upload_status ADD COLUMN callsign TEXT;
```

New status flow:
```
'uploading' → 'pending_verification' → 'uploaded' or 'failed'
```

- `job_id`: POTA's job ID for matching (nullable until found)
- `verified_inserted`: Actual QSOs inserted per POTA (vs `qso_count` we submitted)
- `callsign`: Station callsign used (for job matching)

## Immediate Polling After Upload

After HTTP 200, instead of marking `'uploaded'` immediately:

1. Set status = `'pending_verification'`
2. Poll `get_upload_jobs()` up to 3 times (5s, 10s, 15s delays)
3. Find matching job by: `park_ref` + `callsign` + submitted time within 5 minutes
4. If `job.status == 2` (complete):
   - If `job.inserted > 0` → mark `'uploaded'`, store `job_id` + `verified_inserted`
   - If `job.inserted == 0` → mark `'failed'` (POTA rejected all QSOs)
5. If `job.status >= 3` (error) → mark `'failed'` with error
6. If not found or still processing → leave as `'pending_verification'`

Total wait: ~30 seconds max. Most POTA jobs complete in 5-15 seconds.

## Background Verification

For uploads left in `'pending_verification'` (polling timed out or server restarted):

In `sync_worker.rs`, add a periodic check (every 60 seconds):

1. Query pending verifications started within last hour
2. Group by `user_id` (one POTA auth per user)
3. For each user with pending uploads:
   - Fetch `get_upload_jobs()`
   - Match jobs to pending records by `park_ref` + time window
   - Update status based on job outcome
4. Mark any `pending_verification` older than 1 hour as `'failed'`

## Job Matching Logic

```rust
fn find_matching_job(
    jobs: &[PotaUploadJob],
    park_ref: &str,
    started_at: DateTime<Utc>,
    callsign: &str,
) -> Option<&PotaUploadJob> {
    jobs.iter().find(|job| {
        job.reference == park_ref
        && job.callsign_used.as_deref() == Some(callsign)
        && job_submitted_within(job, started_at, Duration::minutes(5))
    })
}
```

## Files to Modify

| File | Changes |
|------|---------|
| `src/db/mod.rs` | Migration for new columns; `mark_pota_upload_pending_verification()`, `get_pending_pota_verifications()`, update existing methods |
| `src/pota/mod.rs` | `verify_upload_job()` with polling; `find_matching_job()` helper |
| `src/sync_worker.rs` | `verify_pending_pota_uploads()` task in main sync loop |
| `src/web/mod.rs` | Update SSE upload handler for verification status |

## Implementation Order

1. DB schema migration + new methods
2. Job matching + verification logic in `pota/mod.rs`
3. Integrate verification into upload flow
4. Add background verification to sync worker
5. Update SSE messages
