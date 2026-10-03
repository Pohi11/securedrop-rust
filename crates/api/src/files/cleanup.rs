//! Background worker that reclaims abandoned uploads.
//!
//! Without it, a client that starts an upload and walks away would leave (a) quota reserved
//! forever and (b) multipart parts in S3 that are billed but invisible. The S3 lifecycle rule
//! `AbortIncompleteMultipartUpload` (Terraform) is the storage-side backstop; this worker keeps
//! the *database* consistent with storage.

use std::time::Duration;

use tokio::task::JoinHandle;

use super::{repo, service::purge_objects};
use crate::{error::AppResult, state::AppState};

const BATCH: i64 = 100;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupStats {
    pub expired: u64,
    pub purged: u64,
}

/// Spawn the periodic worker. Every replica runs one; `FOR UPDATE SKIP LOCKED` means they
/// split the work instead of fighting over it, so no leader election is needed.
pub fn spawn(state: AppState) -> JoinHandle<()> {
    let interval = state.config.uploads.cleanup_interval;
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval.max(Duration::from_secs(1)));
        // If a run takes longer than the interval, don't fire a burst of catch-up runs.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match run_once(&state).await {
                Ok(stats) if stats != CleanupStats::default() => {
                    tracing::info!(
                        expired = stats.expired,
                        purged = stats.purged,
                        "upload cleanup"
                    );
                }
                Ok(_) => {}
                Err(err) => tracing::error!(error = ?err, "upload cleanup failed"),
            }
        }
    })
}

/// One cleanup pass: expire stale pending uploads, then purge storage for failed/deleted files.
pub async fn run_once(state: &AppState) -> AppResult<CleanupStats> {
    let mut stats = CleanupStats {
        expired: repo::expire_pending(&state.db, BATCH).await?,
        ..Default::default()
    };

    // Claim a batch inside a transaction so other replicas skip these rows while we work.
    // This holds row locks across S3 calls, a deliberate trade-off: the rows are only ever
    // touched by this worker, and SKIP LOCKED means nobody waits on them.
    let mut tx = state.db.begin().await?;
    let targets = repo::claim_unpurged(&mut *tx, BATCH).await?;
    for target in &targets {
        match purge_objects(state, &target.object_key, target.s3_upload_id.as_deref()).await {
            Ok(()) => {
                // Must go through the same transaction that holds the row lock. Using another
                // pool connection here would wait on our own lock forever (self-deadlock).
                repo::mark_purged(&mut *tx, target.id).await?;
                stats.purged += 1;
            }
            Err(err) => {
                tracing::warn!(error = format!("{err:#}"), file_id = %target.id, "purge failed; will retry")
            }
        }
    }
    tx.commit().await?;

    metrics::counter!("securedrop_cleanup_expired_total").increment(stats.expired);
    metrics::counter!("securedrop_cleanup_purged_total").increment(stats.purged);
    Ok(stats)
}
