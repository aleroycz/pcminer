// SPDX-License-Identifier: GPL-3.0-or-later
//
// MicroMiner OS - PC share miner: shared UI/worker state.
//
// Copyright (C) 2026 Vakea

use std::collections::VecDeque;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq)]
pub enum Phase {
    Idle,
    Discovering,
    Connecting,
    WaitingPair,
    Mining,
    Paused,
    Error,
}

impl Phase {
    pub fn label(&self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Discovering => "discovering",
            Phase::Connecting => "connecting",
            Phase::WaitingPair => "awaiting confirmation",
            Phase::Mining => "mining",
            Phase::Paused => "paused",
            Phase::Error => "error",
        }
    }
}

pub struct AppState {
    pub phase: Phase,
    pub status_detail: String,

    pub device_name: String,
    pub device_fp: String, // short fingerprint of the phone's pubkey
    pub my_fp: String,     // short fingerprint of this PC's pubkey

    pub armed: bool, // phone is handing out work (its miner is armed)
    pub current_tag: u32,

    pub hashrate: f64, // H/s, smoothed
    pub total_hashes: u64,

    pub found: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub stale: u64,

    pub threads: usize,
    /// "GPU" / "CPU" / "-" - what the active sweep is using.
    pub backend: String,
    /// Last GPU temp C (-1 = unknown).
    pub gpu_temp_c: i32,
    /// OEM-reported fan % (-1 = unknown / N/A).
    pub gpu_fan_pct: i32,
    /// Thermal band label: ok / warm / hot / critical.
    pub thermal_band: String,
    pub log: VecDeque<String>,

    // control flags set by the UI, read by the worker
    pub want_quit: bool,
    pub want_pause: bool,
    pub want_rescan: bool,

    pub started: Instant,
}

impl AppState {
    pub fn new(my_fp: String, threads: usize) -> Self {
        AppState {
            phase: Phase::Idle,
            status_detail: String::new(),
            device_name: String::new(),
            device_fp: String::new(),
            my_fp,
            armed: false,
            current_tag: 0,
            hashrate: 0.0,
            total_hashes: 0,
            found: 0,
            accepted: 0,
            rejected: 0,
            stale: 0,
            threads,
            backend: "—".into(),
            gpu_temp_c: -1,
            gpu_fan_pct: -1,
            thermal_band: "ok".into(),
            log: VecDeque::with_capacity(256),
            want_quit: false,
            want_pause: false,
            want_rescan: false,
            started: Instant::now(),
        }
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        let line = msg.into();
        let stamped = format!("{}  {}", short_clock(), line);
        self.log.push_back(stamped);
        while self.log.len() > 200 {
            self.log.pop_front();
        }
    }

    pub fn set_phase(&mut self, p: Phase, detail: impl Into<String>) {
        self.phase = p;
        self.status_detail = detail.into();
    }
}

fn short_clock() -> String {
    // Local wall-clock HH:MM:SS without pulling in a date crate.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Human-readable hashrate.
pub fn fmt_hashrate(h: f64) -> String {
    if h >= 1e9 {
        format!("{:.2} GH/s", h / 1e9)
    } else if h >= 1e6 {
        format!("{:.2} MH/s", h / 1e6)
    } else if h >= 1e3 {
        format!("{:.2} kH/s", h / 1e3)
    } else {
        format!("{h:.0} H/s")
    }
}
