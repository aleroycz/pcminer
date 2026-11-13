// SPDX-License-Identifier: GPL-3.0-or-later
//
// Safe GPU thermal governor for pcminer.
//
// Design (fail-safe, no vendor SDK link):
//   - Read GPU temp / power via `nvidia-smi` (driver ICD present on NVIDIA boxes).
//   - When warm: lower the software power limit (heat drops; OEM fans ramp with load).
//   - When hot/critical: stop hashing until cool (hysteresis), keep power capped.
//   - On drop/shutdown: always restore the original power limit.
//   - Never lowers fans; never raises clocks; never mines through a critical reading.
//
// AMD/Intel GPUs: no sensor backend yet - GPU sweeps run without temp guard and
// a warning is logged once. CPU-only mining is load-limited by the reserved core.
//
// Copyright (C) 2026 Vakea

use std::process::Command;
use std::time::{Duration, Instant};

use crate::config::ThermalConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalBand {
    /// Temp unknown or comfortably below pause threshold.
    Ok,
    /// Approaching limit - power-capped, still allowed to hash.
    Warm,
    /// Must not hash until resume hysteresis clears.
    Hot,
    /// Hard ceiling - longer mandatory cool-down.
    Critical,
}

impl ThermalBand {
    pub fn label(self) -> &'static str {
        match self {
            ThermalBand::Ok => "ok",
            ThermalBand::Warm => "warm",
            ThermalBand::Hot => "hot",
            ThermalBand::Critical => "critical",
        }
    }

    pub fn must_pause(self) -> bool {
        matches!(self, ThermalBand::Hot | ThermalBand::Critical)
    }
}

#[derive(Debug, Clone)]
pub struct ThermalSample {
    pub temp_c: Option<i32>,
    pub fan_pct: Option<u32>,
    #[allow(dead_code)]
    pub power_w: Option<u32>,
    pub band: ThermalBand,
    pub note: String,
}

pub struct ThermalGuard {
    cfg: ThermalConfig,
    enabled: bool,
    has_nvidia: bool,
    warned_no_sensor: bool,
    /// Original nvidia-smi power limit (watts), restored on cool/shutdown.
    baseline_pl_w: Option<u32>,
    capped_pl_w: Option<u32>,
    band: ThermalBand,
    paused_since: Option<Instant>,
    last_poll: Instant,
    last_temp_c: Option<i32>,
    last_fan_pct: Option<u32>,
    last_note: String,
}

impl ThermalGuard {
    pub fn new(cfg: ThermalConfig) -> Self {
        let has_nvidia = nvidia_smi_available();
        let enabled = cfg.enabled;
        ThermalGuard {
            cfg,
            enabled,
            has_nvidia,
            warned_no_sensor: false,
            baseline_pl_w: None,
            capped_pl_w: None,
            band: ThermalBand::Ok,
            paused_since: None,
            last_poll: Instant::now() - Duration::from_secs(60),
            last_temp_c: None,
            last_fan_pct: None,
            last_note: if has_nvidia {
                "NVIDIA thermal sensors ready".into()
            } else {
                "no NVIDIA smi — GPU thermal pause unavailable".into()
            },
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn has_sensor(&self) -> bool {
        self.has_nvidia
    }

    /// Poll sensors (rate-limited) and apply safe cool-down actions.
    /// `gpu_active` is true when the OpenCL/GPU backend is (or would be) hashing.
    pub fn tick(&mut self, gpu_active: bool) -> ThermalSample {
        if !self.enabled {
            return ThermalSample {
                temp_c: None,
                fan_pct: None,
                power_w: None,
                band: ThermalBand::Ok,
                note: "thermal guard disabled".into(),
            };
        }

        if !self.has_nvidia {
            if gpu_active && !self.warned_no_sensor {
                self.warned_no_sensor = true;
                self.last_note =
                    "GPU mining without temp sensors — cannot auto-pause on overheat".into();
            }
            return ThermalSample {
                temp_c: None,
                fan_pct: None,
                power_w: None,
                band: ThermalBand::Ok,
                note: self.last_note.clone(),
            };
        }

        let interval = Duration::from_millis(self.cfg.poll_ms.max(500));
        if self.last_poll.elapsed() >= interval {
            self.last_poll = Instant::now();
            if let Some((t, fan, pl)) = query_nvidia() {
                self.last_temp_c = Some(t);
                self.last_fan_pct = fan;
                if self.baseline_pl_w.is_none() {
                    if let Some(w) = pl {
                        self.baseline_pl_w = Some(w);
                    }
                }
                self.recompute_band(t);
                self.apply_cooling(t, gpu_active);
            } else {
                // Lost sensors while we had a reading -> fail safe (pause).
                if self.last_temp_c.is_some() {
                    self.band = ThermalBand::Hot;
                    self.last_note = "temp read failed — pausing until sensors recover".into();
                    if self.paused_since.is_none() {
                        self.paused_since = Some(Instant::now());
                    }
                }
            }
        }

        ThermalSample {
            temp_c: self.last_temp_c,
            fan_pct: self.last_fan_pct,
            power_w: self.capped_pl_w.or(self.baseline_pl_w),
            band: self.band,
            note: self.last_note.clone(),
        }
    }

    fn recompute_band(&mut self, temp_c: i32) {
        let pause_at = self.cfg.pause_c;
        let resume_at = self.cfg.resume_c.min(pause_at.saturating_sub(3));
        let warm_at = self.cfg.warm_c.min(pause_at.saturating_sub(1));
        let crit_at = self.cfg.critical_c.max(pause_at + 1);

        let prev = self.band;
        let next = if temp_c >= crit_at {
            ThermalBand::Critical
        } else if self.band.must_pause() {
            // Hysteresis: stay paused until we cool past resume_at.
            if temp_c <= resume_at {
                ThermalBand::Ok
            } else if temp_c >= pause_at {
                if temp_c >= crit_at {
                    ThermalBand::Critical
                } else {
                    ThermalBand::Hot
                }
            } else {
                ThermalBand::Hot // still cooling through the gap
            }
        } else if temp_c >= pause_at {
            ThermalBand::Hot
        } else if temp_c >= warm_at {
            ThermalBand::Warm
        } else {
            ThermalBand::Ok
        };

        if next.must_pause() && !prev.must_pause() {
            self.paused_since = Some(Instant::now());
            self.last_note = format!("thermal pause at {temp_c}°C (resume ≤{resume_at}°C)");
        } else if !next.must_pause() && prev.must_pause() {
            // Honour a minimum cool-down so we don't flap.
            let min_pause = Duration::from_millis(self.cfg.min_pause_ms);
            if let Some(since) = self.paused_since {
                if since.elapsed() < min_pause {
                    self.band = prev;
                    self.last_note =
                        format!("cooling… {}°C (min pause {}s)", temp_c, min_pause.as_secs());
                    return;
                }
            }
            self.paused_since = None;
            self.last_note = format!("thermal clear at {temp_c}°C — resuming");
        } else if next == ThermalBand::Warm {
            self.last_note = format!("warm {temp_c}°C — power capped, fans follow OEM curve");
        } else if next == ThermalBand::Ok {
            self.last_note = format!("GPU {temp_c}°C ok");
        } else if next == ThermalBand::Critical {
            self.last_note = format!("CRITICAL {temp_c}°C — hashing stopped");
        }

        self.band = next;
    }

    fn apply_cooling(&mut self, temp_c: i32, gpu_active: bool) {
        if !self.cfg.power_cap {
            return;
        }
        let Some(base) = self.baseline_pl_w else {
            return;
        };

        // Only touch the power limit while GPU work is in play or we are cooling down from a hot spell.
        let want_cap = match self.band {
            ThermalBand::Ok => None,
            ThermalBand::Warm => Some(pct_watts(base, self.cfg.warm_power_pct)),
            ThermalBand::Hot | ThermalBand::Critical => {
                Some(pct_watts(base, self.cfg.hot_power_pct))
            }
        };

        if let Some(target) = want_cap {
            if self.capped_pl_w != Some(target) && (gpu_active || self.band.must_pause()) {
                if set_power_limit_w(target) {
                    self.capped_pl_w = Some(target);
                    let _ = temp_c;
                }
            }
        } else if self.capped_pl_w.is_some() {
            if set_power_limit_w(base) {
                self.capped_pl_w = None;
            }
        }

        // Fan hint: stock driver ramps fans with temp/power. We deliberately do
        // not force a manual fan % on GeForce (often locked; unsafe if stuck high/low).
        // Pausing + power-cap is the portable safe cool-down.
        let _ = self.cfg.fan_boost_pct;
    }

    /// Restore OEM power limit. Call on quit / disconnect.
    pub fn restore(&mut self) {
        if let Some(base) = self.baseline_pl_w {
            if self.capped_pl_w.is_some() {
                let _ = set_power_limit_w(base);
                self.capped_pl_w = None;
            }
        }
        self.band = ThermalBand::Ok;
        self.paused_since = None;
    }
}

impl Drop for ThermalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

fn pct_watts(base: u32, pct: u32) -> u32 {
    let pct = pct.clamp(40, 100);
    let w = (base as u64 * pct as u64) / 100;
    w.max(30) as u32 // never request an absurdly low limit
}

fn nvidia_smi_available() -> bool {
    Command::new("nvidia-smi")
        .arg("-L")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns (temp_c, fan_pct, power_limit_w).
fn query_nvidia() -> Option<(i32, Option<u32>, Option<u32>)> {
    let out = Command::new("nvidia-smi")
        .args([
            "--query-gpu=temperature.gpu,fan.speed,power.limit",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next()?.trim();
    // e.g. "72, 45, 170.00" or "72, [N/A], 115.00"
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
    if parts.is_empty() {
        return None;
    }
    let temp: i32 = parse_num(parts[0])? as i32;
    let fan = parts.get(1).and_then(|s| parse_num(s)).map(|v| v as u32);
    let pl = parts.get(2).and_then(|s| parse_num(s)).map(|v| v as u32);
    // Sanity: refuse absurd readings so we never act on garbage.
    if !(1..=120).contains(&temp) {
        return None;
    }
    Some((temp, fan, pl))
}

fn parse_num(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("n/a") || t.eq_ignore_ascii_case("[n/a]") {
        return None;
    }
    // power.limit may be "170.00 W" even with nounits on some drivers - strip junk.
    let cleaned: String = t
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    cleaned.parse().ok()
}

fn set_power_limit_w(watts: u32) -> bool {
    // Best-effort; may require admin. Failure is non-fatal - pause still protects silicon.
    Command::new("nvidia-smi")
        .args(["-pl", &watts.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pct_watts_clamps() {
        assert_eq!(pct_watts(200, 80), 160);
        assert_eq!(pct_watts(200, 10), 80); // pct clamp to 40%
        assert!(pct_watts(50, 40) >= 30);
    }

    #[test]
    fn parse_num_na() {
        assert!(parse_num("[N/A]").is_none());
        assert_eq!(parse_num("72").unwrap() as i32, 72);
        assert_eq!(parse_num("170.00").unwrap() as u32, 170);
    }
}
