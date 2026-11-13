// SPDX-License-Identifier: GPL-3.0-or-later
//
// MicroMiner OS - PC share miner: persistent config + identity.
//
// Copyright (C) 2026 Vakea

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::nacl;

/// Serde config: box secret, worker name, optional fixed host, thread count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// This PC's long-term box secret key (hex, 32 bytes).
    pub secret_key: String,
    /// Friendly worker name shown on the phone's pairing modal.
    pub worker_name: String,
    /// Optional fixed phone address "ip:port" to skip UDP discovery.
    #[serde(default)]
    pub host: Option<String>,
    /// Number of CPU mining threads (0 = auto = all cores minus one for UI/OS).
    #[serde(default)]
    pub threads: usize,
    /// Prefer OpenCL GPU when the `gpu` feature is built (default true).
    #[serde(default = "default_use_gpu")]
    pub use_gpu: bool,
    /// Raise NVIDIA power/clocks to driver max while mining (nvidia-smi).
    #[serde(default = "default_true")]
    pub unlock_gpu_perf: bool,
    /// UDP/TCP port the phone listens on.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Safe GPU thermal pause / power-cap (NVIDIA via nvidia-smi).
    #[serde(default)]
    pub thermal: ThermalConfig,
}

fn default_use_gpu() -> bool {
    true
}

/// Conservative defaults - prefer pause over cooking the card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThermalConfig {
    /// Master switch (default on).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Start easing (power cap) at this GPU C.
    #[serde(default = "default_warm_c")]
    pub warm_c: i32,
    /// Stop hashing at/above this GPU C.
    #[serde(default = "default_pause_c")]
    pub pause_c: i32,
    /// Resume hashing only after cooling to this C (hysteresis).
    #[serde(default = "default_resume_c")]
    pub resume_c: i32,
    /// Hard ceiling - longer mandatory cool-down messaging.
    #[serde(default = "default_critical_c")]
    pub critical_c: i32,
    /// Minimum time to stay paused once hot (ms).
    #[serde(default = "default_min_pause_ms")]
    pub min_pause_ms: u64,
    /// Sensor poll interval (ms).
    #[serde(default = "default_poll_ms")]
    pub poll_ms: u64,
    /// Lower nvidia-smi power limit when warm/hot (safe heat cut).
    #[serde(default = "default_true")]
    pub power_cap: bool,
    /// Power limit % of baseline while warm.
    #[serde(default = "default_warm_power_pct")]
    pub warm_power_pct: u32,
    /// Power limit % of baseline while hot/critical.
    #[serde(default = "default_hot_power_pct")]
    pub hot_power_pct: u32,
    /// Reserved for future unlocked-fan paths (GeForce usually ignores).
    #[serde(default = "default_fan_boost_pct")]
    pub fan_boost_pct: u32,
}

fn default_true() -> bool {
    true
}
fn default_warm_c() -> i32 {
    75
}
fn default_pause_c() -> i32 {
    85
}
fn default_resume_c() -> i32 {
    75
}
fn default_critical_c() -> i32 {
    92
}
fn default_min_pause_ms() -> u64 {
    8_000
}
fn default_poll_ms() -> u64 {
    2_000
}
fn default_warm_power_pct() -> u32 {
    80
}
fn default_hot_power_pct() -> u32 {
    60
}
fn default_fan_boost_pct() -> u32 {
    80
}

impl Default for ThermalConfig {
    fn default() -> Self {
        ThermalConfig {
            enabled: true,
            warm_c: default_warm_c(),
            pause_c: default_pause_c(),
            resume_c: default_resume_c(),
            critical_c: default_critical_c(),
            min_pause_ms: default_min_pause_ms(),
            poll_ms: default_poll_ms(),
            power_cap: true,
            warm_power_pct: default_warm_power_pct(),
            hot_power_pct: default_hot_power_pct(),
            fan_boost_pct: default_fan_boost_pct(),
        }
    }
}

impl ThermalConfig {
    /// Clamp operator values into a non-suicidal range.
    pub fn sanitized(&self) -> ThermalConfig {
        let mut t = self.clone();
        t.warm_c = t.warm_c.clamp(50, 95);
        t.pause_c = t.pause_c.clamp(t.warm_c + 1, 100);
        t.resume_c = t.resume_c.clamp(40, t.pause_c - 2);
        t.critical_c = t.critical_c.clamp(t.pause_c + 1, 105);
        t.min_pause_ms = t.min_pause_ms.clamp(3_000, 120_000);
        t.poll_ms = t.poll_ms.clamp(500, 10_000);
        t.warm_power_pct = t.warm_power_pct.clamp(50, 100);
        t.hot_power_pct = t.hot_power_pct.clamp(40, t.warm_power_pct);
        t.fan_boost_pct = t.fan_boost_pct.clamp(50, 100);
        t
    }
}

fn default_port() -> u16 {
    48510
}

impl Config {
    pub fn secret_bytes(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        if let Ok(v) = hex::decode(&self.secret_key) {
            if v.len() == 32 {
                b.copy_from_slice(&v);
            }
        }
        b
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        nacl::box_public_from_secret(&self.secret_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public_bytes())
    }
}

pub fn config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("microminer").join("pcminer.toml")
}

/// Load the config, creating a fresh identity on first run.
pub fn load_or_init() -> Result<Config> {
    let path = config_path();
    if path.exists() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).context("parsing config")?;
        return Ok(cfg);
    }

    let (_pk, sk) = nacl::box_keypair();
    let name = hostname_guess();
    let cfg = Config {
        secret_key: hex::encode(sk),
        worker_name: name,
        host: None,
        threads: 0,
        use_gpu: true,
        unlock_gpu_perf: true,
        port: default_port(),
        thermal: ThermalConfig::default(),
    };
    save(&cfg)?;
    Ok(cfg)
}

pub fn save(cfg: &Config) -> Result<()> {
    let path = config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let text = toml::to_string_pretty(cfg).context("serializing config")?;
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn hostname_guess() -> String {
    for key in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                return format!("pc-{v}");
            }
        }
    }
    "pc-worker".to_string()
}
