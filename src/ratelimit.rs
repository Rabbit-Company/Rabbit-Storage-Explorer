//! A shared byte-rate limiter (token bucket) for pacing transfers.
//!
//! One limiter is shared (via `Arc`) across every concurrent download task in a
//! session, so the configured cap is a *global* ceiling: N parallel downloads
//! share it instead of each getting the full rate. The rate lives in an atomic
//! and can be changed live (from `SetSettings`) without tearing anything down.
//! A rate of 0 means unlimited - `acquire` then returns immediately.
//!
//! `acquire(n)` is meant to be called *after* the bytes have been read, so the
//! delay it introduces paces the *next* read. Over time the average throughput
//! converges to the configured rate, and because we stop pulling from the socket
//! once the budget is spent, TCP flow control back-pressures the sender - this
//! throttles the actual connection, not just post-hoc accounting.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Smallest burst the bucket will ever allow, in bytes. This MUST exceed the
/// largest single `acquire` (a download charges at most one ~256 KiB read at a
/// time) so that even a very low rate can accumulate enough tokens to release
/// one read. If the capacity could fall below `n`, an `acquire(n)` would refill
/// forever without reaching `n` and never complete. 1 MiB sits comfortably above
/// any single download chunk while keeping the burst modest at low rates.
const BURST_FLOOR: f64 = 1024.0 * 1024.0;

pub struct RateLimiter {
	/// Target rate in bytes/second. 0 = unlimited.
	rate: AtomicU64,
	bucket: Mutex<Bucket>,
}

struct Bucket {
	/// Available budget in bytes, accumulated since the last refill.
	tokens: f64,
	last_refill: Instant,
}

impl RateLimiter {
	/// Create a limiter. `bytes_per_sec == 0` means unlimited.
	pub fn new(bytes_per_sec: u64) -> Self {
		Self {
			rate: AtomicU64::new(bytes_per_sec),
			bucket: Mutex::new(Bucket {
				tokens: 0.0,
				last_refill: Instant::now(),
			}),
		}
	}

	/// Change the rate live. `bytes_per_sec == 0` disables throttling. Every
	/// clone sharing this `Arc` sees the change on its next `acquire`.
	pub fn set_rate(&self, bytes_per_sec: u64) {
		self.rate.store(bytes_per_sec, Ordering::Relaxed);
	}

	/// Block until `n` bytes' worth of budget is available, then consume it.
	/// Returns immediately when unlimited. Cancel-safe: if the returned future
	/// is dropped mid-wait, no tokens are consumed (the bucket is only debited
	/// once availability is confirmed, before any await).
	pub async fn acquire(&self, n: u64) {
		loop {
			let rate = self.rate.load(Ordering::Relaxed);
			if rate == 0 {
				return; // unlimited
			}
			let rate = rate as f64;
			let capacity = rate.max(BURST_FLOOR);

			// Refill and check under the lock; never held across an await.
			let wait = {
				let mut b = self.bucket.lock().unwrap();
				let now = Instant::now();
				let elapsed = now.duration_since(b.last_refill).as_secs_f64();
				b.last_refill = now;
				b.tokens = (b.tokens + elapsed * rate).min(capacity);

				let need = n as f64;
				if b.tokens >= need {
					b.tokens -= need;
					return;
				}
				// Time for the deficit to refill. `need <= capacity` is guaranteed
				// by BURST_FLOOR, so this always eventually makes progress.
				(need - b.tokens) / rate
			};

			tokio::time::sleep(Duration::from_secs_f64(wait)).await;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn unlimited_is_instant() {
		// rate == 0 returns before any sleep, so this is deterministic.
		let rl = RateLimiter::new(0);
		let start = Instant::now();
		rl.acquire(10_000_000).await;
		assert!(start.elapsed() < Duration::from_millis(50));
	}

	#[tokio::test]
	async fn live_rate_change_takes_effect() {
		let rl = RateLimiter::new(1_000_000);
		rl.set_rate(0); // switch to unlimited
		let start = Instant::now();
		rl.acquire(50_000_000).await;
		assert!(start.elapsed() < Duration::from_millis(50));
	}

	#[tokio::test]
	async fn paces_to_rate() {
		// 1 MB/s, empty bucket: acquiring 200 KB must wait ~0.2s of accumulation.
		// Real-time test (the limiter uses the std clock); loose lower bound only.
		let rl = RateLimiter::new(1_000_000);
		let start = Instant::now();
		rl.acquire(200_000).await;
		assert!(
			start.elapsed() >= Duration::from_millis(150),
			"expected ~0.2s pacing, got {:?}",
			start.elapsed()
		);
	}
}
