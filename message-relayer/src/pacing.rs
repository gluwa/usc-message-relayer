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
#[derive(Debug, Default)]
pub struct RateLimitPacer {
    level: u32,
}

impl RateLimitPacer {
    /// Record an iteration outcome and return the extra cooldown to sleep before the next tick
    /// (zero when calm). Escalates on rate-limited failures, decays one level per clean pass.
    pub fn after(&mut self, rate_limited: bool) -> Duration {
        if rate_limited {
            self.level = (self.level + 1).min(LEVEL_CAP);
        } else {
            self.level = self.level.saturating_sub(1);
        }
        if self.level == 0 {
            Duration::ZERO
        } else {
            BASE * 2u32.pow(self.level - 1)
        }
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
        let mut last = Duration::ZERO;
        for _ in 0..8 {
            let d = p.after(true);
            assert!(d >= last, "cooldown must not shrink while rate-limited");
            last = d;
        }
        assert_eq!(last, BASE * 2u32.pow(LEVEL_CAP - 1), "capped at LEVEL_CAP");
        // One clean pass steps DOWN one level, not to zero — a loop colliding every other tick
        // must stay damped instead of oscillating between full speed and full cooldown.
        let d = p.after(false);
        assert_eq!(d, BASE * 2u32.pow(LEVEL_CAP - 2));
        // Sustained calm drains it to zero.
        for _ in 0..LEVEL_CAP {
            p.after(false);
        }
        assert_eq!(p.after(false), Duration::ZERO);
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
