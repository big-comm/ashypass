//! Argon2id parameter auto-tuning.
//!
//! Benchmarks Argon2id on the current machine and picks params whose derivation
//! takes roughly `target_millis`. Higher memory cost is preferred over higher
//! time cost for the same total work (per Argon2 paper).
//!
//! Stored under `Settings::argon2` so future master password rehashes use the
//! tuned values. Existing PHC hashes embed their original params and remain
//! verifiable regardless.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunedParams {
    pub t_cost: u32,
    pub m_cost_kib: u32,
    pub p_cost: u32,
}

impl Default for TunedParams {
    fn default() -> Self {
        Self {
            t_cost: 3,
            m_cost_kib: 65536, // 64 MiB
            p_cost: 4,
        }
    }
}

impl TunedParams {
    pub fn to_argon2_params(self) -> Result<Params, argon2::Error> {
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
    }

    fn measure_ms(self) -> Option<u128> {
        let params = self.to_argon2_params().ok()?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        let salt = [0x42u8; 16];
        let pwd = b"benchmark-password";
        let t0 = Instant::now();
        argon.hash_password_into(pwd, &salt, &mut out).ok()?;
        Some(t0.elapsed().as_millis())
    }
}

/// Find Argon2 params whose KDF runtime is close to `target_millis`.
///
/// Walks m_cost from 64 MiB upwards, doubling until the time crosses the
/// target. Caps memory at `max_m_cost_kib` to avoid runaway allocations on
/// machines with lots of RAM (default 1 GiB).
pub fn autotune(target_millis: u64, max_m_cost_kib: u32) -> TunedParams {
    let t_cost: u32 = 3;
    let p_cost: u32 = num_cpus();

    let mut m_cost: u32 = 65536; // 64 MiB
    let mut best = TunedParams {
        t_cost,
        m_cost_kib: m_cost,
        p_cost,
    };
    let mut best_ms: u128 = best.measure_ms().unwrap_or(0);

    // Grow memory geometrically until we cross the target or hit the cap.
    while m_cost < max_m_cost_kib {
        let next = (m_cost.saturating_mul(2)).min(max_m_cost_kib);
        let candidate = TunedParams {
            t_cost,
            m_cost_kib: next,
            p_cost,
        };
        let Some(elapsed) = candidate.measure_ms() else {
            break;
        };
        if elapsed >= target_millis as u128 {
            // Choose whichever (current best vs candidate) is closer to target.
            let prev_diff = (target_millis as i128 - best_ms as i128).abs();
            let new_diff = (target_millis as i128 - elapsed as i128).abs();
            if new_diff < prev_diff {
                best = candidate;
            }
            return best;
        }
        best = candidate;
        best_ms = elapsed;
        m_cost = next;
        if m_cost == max_m_cost_kib {
            break;
        }
    }

    // Hit the memory cap before reaching the target; bump t_cost to compensate.
    let mut t = t_cost;
    while best_ms < target_millis as u128 && t < 12 {
        t += 1;
        let candidate = TunedParams {
            t_cost: t,
            m_cost_kib: best.m_cost_kib,
            p_cost,
        };
        let Some(elapsed) = candidate.measure_ms() else {
            break;
        };
        best = candidate;
        best_ms = elapsed;
    }
    best
}

fn num_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| (n.get() as u32).clamp(1, 8))
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_produce_valid_params() {
        assert!(TunedParams::default().to_argon2_params().is_ok());
    }

    #[test]
    fn measure_returns_some_for_defaults() {
        let ms = TunedParams::default().measure_ms();
        assert!(ms.is_some());
    }
}
