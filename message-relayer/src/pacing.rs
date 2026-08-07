//! Adaptive pacing for the relayer's periodic destination-chain read loops.
//!
//! The relayer shares its destination RPC (and often the API key) with the attestor fleet, whose
//! per-block fetches arrive in synchronized bursts. Plan-level RPS caps therefore reject a slice
//! of the relayer's reads whenever the fleet spikes — observed live on 2026-08-07 when nine
//! catching-up attestors starved every relayer loop on a shared Chainstack key (`-32005: You've
//! exceeded the RPS limit`). The loops all retry, but retrying at the base cadence keeps paying
//! into the very limit that is rejecting us.
//!
//! [`RateLimitPacer`] adds an escalating cooldown after rate-limited iterations and decays it one
//! level per clean iteration (gradual, not instant — a loop that collides on every other tick
//! stays damped instead of oscillating). Non-rate-limit errors are untouched: a genuine outage
//! should keep the loop's own retry/health semantics.

use std::time::Duration;

/// Escalation cap: `BASE << LEVEL_CAP` bounds the added cooldown (with `BASE` = 5s, level 5 =
/// 160s ≈ 2.5 min on top of the loop's own interval — long enough for a fleet burst to pass,
/// short enough that discovery lag stays in operator-tolerable territory).
const LEVEL_CAP: u32 = 5;
const BASE: Duration = Duration::from_secs(5);

/// Per-loop rate-limit damper. One instance per periodic loop, fed every iteration outcome.
///
/// Deliberately **deferral-based, not sleep-based**: the loop checks [`Self::deferring`] at each
/// tick and skips the iteration while a window is active. Sleeping inside a `select!` arm would
/// (a) stop sibling arms from being polled (the set-update aggregator must keep draining votes),
/// and (b) let long cooldowns push a worker past the health watchdog's `PROGRESS_DEADLINE`, whose
/// restart would reset every pacer and re-burst the shared key — a restart storm worse than the
/// collision being damped (bugbot).
#[derive(Debug, Default)]
pub struct RateLimitPacer {
    level: u32,
    defer_until: Option<std::time::Instant>,
}

impl RateLimitPacer {
    /// Record an iteration outcome. A rate-limited failure escalates the level and arms a deferral
    /// window (`BASE << (level-1)`, capped); a clean pass decays ONE level (gradual, so a loop that
    /// collides every other tick stays damped) and arms nothing — clean iterations are never
    /// slowed, only failed-because-limited ones defer the next attempts.
    pub fn after(&mut self, rate_limited: bool) {
        if rate_limited {
            self.level = (self.level + 1).min(LEVEL_CAP);
            self.defer_until = Some(std::time::Instant::now() + BASE * 2u32.pow(self.level - 1));
        } else {
            self.level = self.level.saturating_sub(1);
        }
    }

    /// Time remaining in an active deferral window, `None` when the loop should run its tick.
    pub fn deferring(&self) -> Option<Duration> {
        let until = self.defer_until?;
        let now = std::time::Instant::now();
        (now < until).then(|| until - now)
    }
}

/// Whether an error chain looks like provider rate limiting / quota exhaustion. Matches the
/// phrasings observed live plus the common ones: Chainstack's `-32005 … RPS limit`, HTTP 429,
/// Google Blockchain Node Engine's `resource_exhausted` close frames, and generic quota wording.
/// Numeric tokens ("429", "32005") are matched with non-alphanumeric boundaries so block numbers
/// and hex ids containing those digit runs (Sepolia heights currently start 11429…) never
/// misclassify. A false positive only makes one loop wait longer.
pub fn error_looks_rate_limited(text: &str) -> bool {
    let text = text.to_lowercase();
    [
        "resource_exhausted",
        "resource exhausted",
        "rate limit",
        "rps limit",
        "too many requests",
        "quota",
    ]
    .iter()
    .any(|needle| text.contains(needle))
        || contains_standalone(&text, "429")
        || contains_standalone(&text, "32005")
}

/// `needle` bounded by non-alphanumerics (or string edges) — a status/error code, not a digit run
/// inside a block number or hex id.
fn contains_standalone(text: &str, needle: &str) -> bool {
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(pos) = text[start..].find(needle) {
        let i = start + pos;
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let after = i + needle.len();
        let after_ok = after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = i + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalates_to_cap_and_decays_gradually() {
        let mut p = RateLimitPacer::default();
        // Calm loop: nothing armed, nothing deferred.
        p.after(false);
        assert!(p.deferring().is_none(), "clean iterations must never defer");

        let mut last = Duration::ZERO;
        for _ in 0..8 {
            p.after(true);
            let d = p.deferring().expect("rate-limited failure arms a window");
            assert!(
                d >= last.saturating_sub(Duration::from_millis(50)),
                "window must not shrink while rate-limited"
            );
            last = d;
        }
        assert!(
            last <= BASE * 2u32.pow(LEVEL_CAP - 1),
            "window capped at LEVEL_CAP"
        );
        assert!(last > BASE * 2u32.pow(LEVEL_CAP - 2), "reached the cap");

        // Clean passes decay the LEVEL but do not arm new windows: after the current window
        // passes, a decayed-but-nonzero level only matters if another collision happens.
        p.after(false);
        p.after(false);
        assert_eq!(p.level, LEVEL_CAP - 2, "one level per clean pass");
        // A fresh collision after partial decay arms a window sized by the decayed level + 1.
        p.after(true);
        let d = p.deferring().expect("armed");
        assert!(d <= BASE * 2u32.pow(LEVEL_CAP - 2));
    }

    #[test]
    fn classifier_matches_live_provider_phrasings() {
        // Verbatim Chainstack (2026-08-07 incident).
        assert!(error_looks_rate_limited(
            "server returned an error response: error code -32005: You've exceeded the RPS limit \
             available on the current plan. Learn more at ..."
        ));
        // Verbatim Google BNE close frame (2026-08-06 incident).
        assert!(error_looks_rate_limited(
            "Received close frame with data: [ORIGINAL ERROR] generic::resource_exhausted: \
             com.google.apps.framework.request"
        ));
        assert!(error_looks_rate_limited("HTTP 429 Too Many Requests"));
        assert!(error_looks_rate_limited("daily quota exceeded"));
    }

    #[test]
    fn classifier_ignores_block_numbers_and_transients() {
        // Sepolia heights currently contain "429"; contract data can contain any digit run.
        assert!(!error_looks_rate_limited(
            "eth_getLogs from 11429000 to 11429060 failed"
        ));
        assert!(!error_looks_rate_limited("nonce 3200529 already used"));
        assert!(!error_looks_rate_limited(
            "generic::unavailable: Downstream connection unexpectedly closed"
        ));
        assert!(!error_looks_rate_limited("connection refused"));
    }
}
