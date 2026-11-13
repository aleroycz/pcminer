// SPDX-License-Identifier: GPL-3.0-or-later
//
// Safe NVIDIA performance unlock for pcminer (via nvidia-smi only).
//
// GeForce cards often sit in P8 with ~200 MHz clocks while "mining" if nothing
// forces a high-performance state. We raise the power limit to the driver max
// and lock GPU/memory clocks to the advertised maxima so OpenCL sha256d can
// actually use the chip. Everything is restored on Drop.
//
// This is NOT an LHR ethash bypass and does NOT use Tensor Cores (sha256d is
// an OpenCL integer path). It only applies supported nvidia-smi controls.
//
// Copyright (C) 2026 Vakea

use std::process::Command;

#[derive(Debug, Default)]
pub struct NvidiaPerfGuard {
    active: bool,
    orig_pl_w: Option<u32>,
    locked_gpu: bool,
    locked_mem: bool,
    persistence: bool,
    summary: String,
}

impl NvidiaPerfGuard {
    /// No-op placeholder when GPU path is off.
    pub fn inactive() -> Self {
        Self {
            summary: "NVIDIA perf unlock skipped".into(),
            ..Self::default()
        }
    }

    /// Best-effort unlock. Failures are non-fatal (mining still runs).
    pub fn acquire() -> Self {
        if !smi_ok() {
            return Self {
                summary: "nvidia-smi missing — cannot unlock GPU clocks".into(),
                ..Self::default()
            };
        }

        let mut g = Self::default();
        let caps = query_caps();

        // Persistence mode keeps the driver from fully parking the GPU between batches.
        if run_smi(&["-pm", "1"]) {
            g.persistence = true;
        }

        g.orig_pl_w = caps.current_pl.or(caps.default_pl);
        if let Some(max_pl) = caps.max_pl {
            // Only raise; never lower here (thermal governor may cap later).
            let target = max_pl;
            if run_smi(&["-pl", &target.to_string()]) {
                g.active = true;
            }
        }

        // Lock clocks to the driver-reported maxima when the API allows it.
        if let (Some(gmin), Some(gmax)) = (caps.min_gr, caps.max_gr) {
            let arg = format!("{gmin},{gmax}");
            if run_smi(&["-lgc", &arg]) {
                g.locked_gpu = true;
                g.active = true;
            } else if run_smi(&["-lgc", &gmax.to_string()]) {
                g.locked_gpu = true;
                g.active = true;
            }
        }
        if let (Some(mmin), Some(mmax)) = (caps.min_mem, caps.max_mem) {
            let arg = format!("{mmin},{mmax}");
            if run_smi(&["-lmc", &arg]) {
                g.locked_mem = true;
                g.active = true;
            } else if run_smi(&["-lmc", &mmax.to_string()]) {
                g.locked_mem = true;
                g.active = true;
            }
        }

        g.summary = format!(
            "NVIDIA unlock: pl={}→{}W gpu_clk={} mem_clk={} pm={}",
            g.orig_pl_w.map(|v| v.to_string()).unwrap_or("?".into()),
            caps.max_pl.map(|v| v.to_string()).unwrap_or("?".into()),
            if g.locked_gpu {
                caps.max_gr
                    .map(|v| format!("{v}MHz"))
                    .unwrap_or_else(|| "on".into())
            } else {
                "unsupported".into()
            },
            if g.locked_mem {
                caps.max_mem
                    .map(|v| format!("{v}MHz"))
                    .unwrap_or_else(|| "on".into())
            } else {
                "unsupported".into()
            },
            if g.persistence { "on" } else { "off" }
        );
        g
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }

    pub fn restore(&mut self) {
        if self.locked_gpu {
            let _ = run_smi(&["-rgc"]);
            self.locked_gpu = false;
        }
        if self.locked_mem {
            let _ = run_smi(&["-rmc"]);
            self.locked_mem = false;
        }
        if let Some(pl) = self.orig_pl_w.take() {
            let _ = run_smi(&["-pl", &pl.to_string()]);
        }
        // Leave persistence on - harmless and avoids re-init cost next run.
        self.active = false;
    }
}

impl Drop for NvidiaPerfGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

#[derive(Default)]
struct Caps {
    current_pl: Option<u32>,
    default_pl: Option<u32>,
    max_pl: Option<u32>,
    min_gr: Option<u32>,
    max_gr: Option<u32>,
    min_mem: Option<u32>,
    max_mem: Option<u32>,
}

fn smi_ok() -> bool {
    Command::new("nvidia-smi")
        .arg("-L")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_smi(args: &[&str]) -> bool {
    Command::new("nvidia-smi")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn query_caps() -> Caps {
    let mut c = Caps::default();
    if let Some(line) = smi_query(
        "power.limit,power.default_limit,power.max_limit,clocks.max.graphics,clocks.max.memory",
    ) {
        let p: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        c.current_pl = p.first().and_then(|s| parse_num(s));
        c.default_pl = p.get(1).and_then(|s| parse_num(s));
        c.max_pl = p.get(2).and_then(|s| parse_num(s));
        c.max_gr = p.get(3).and_then(|s| parse_num(s));
        c.max_mem = p.get(4).and_then(|s| parse_num(s));
    }
    // Min clocks: use a sane floor so the lock range is valid (not idle P8).
    if let Some(max) = c.max_gr {
        c.min_gr = Some((max * 70 / 100).max(300));
    }
    if let Some(max) = c.max_mem {
        c.min_mem = Some((max * 70 / 100).max(400));
    }
    c
}

fn smi_query(fields: &str) -> Option<String> {
    let out = Command::new("nvidia-smi")
        .args([
            &format!("--query-gpu={fields}"),
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|s| s.trim().to_string())
}

fn parse_num(s: &str) -> Option<u32> {
    let t = s.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("n/a") || t.eq_ignore_ascii_case("[n/a]") {
        return None;
    }
    let cleaned: String = t
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    cleaned.parse::<f64>().ok().map(|v| v as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_num_basic() {
        assert_eq!(parse_num("212.00"), Some(212));
        assert!(parse_num("[N/A]").is_none());
    }
}
