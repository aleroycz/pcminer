// SPDX-License-Identifier: GPL-3.0-or-later
//
// MicroMiner OS - PC share miner: persistent config + identity.
// Copyright (C) 2026 Vakea

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::nacl;

/// On-disk config. The secret key is this PC's long-term box identity; the phone
/// pins the matching public key on first pairing (trust on first use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// This PC's long-term box secret key (hex, 32 bytes).
    pub secret_key: String,
    /// Friendly worker name shown on the phone's pairing modal.
    pub worker_name: String,
    /// Optional fixed phone address "ip:port" to skip UDP discovery.
    #[serde(default)]
    pub host: Option<String>,
    /// Number of CPU mining threads (0 = auto = all cores).
    #[serde(default)]
    pub threads: usize,
    /// UDP/TCP port the phone listens on.
    #[serde(default = "default_port")]
    pub port: u16,
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
        port: default_port(),
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
