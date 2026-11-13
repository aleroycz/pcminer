// SPDX-License-Identifier: GPL-3.0-or-later
//
// MMSHARE1 JOB/RESULT/CAPS parsing (aligned with src/net/share_proto.c).
//
// Copyright (C) 2026 Vakea

use crate::miner::{self, Job};

/// Algorithms this build can sweep.
pub fn algo_supported(algo: &str) -> bool {
    algo.is_empty() || algo == "sha256d" || algo == "verushash"
}

/// True when a CAPS line is an explicit reject (phone refused our algo).
pub fn caps_is_reject(msg: &str) -> bool {
    msg.starts_with("CAPS") && msg.contains("reject")
}

/// CAPS algo must be supported locally; otherwise Err (no silent mismatch).
pub fn negotiate_algo(phone_algo: &str) -> Result<String, String> {
    if algo_supported(phone_algo) {
        let name = if phone_algo.is_empty() {
            "sha256d".to_string()
        } else {
            phone_algo.to_string()
        };
        Ok(name)
    } else {
        Err(format!(
            "algo mismatch: phone offers '{phone_algo}', pcminer supports sha256d+verushash"
        ))
    }
}

/// Parse optional `key=value` tokens from a whitespace-split message.
pub fn kv_u32(parts: &[&str], key: &str) -> Option<u32> {
    let prefix = format!("{key}=");
    parts
        .iter()
        .find_map(|p| p.strip_prefix(&prefix)?.parse().ok())
}

pub fn kv_usize(parts: &[&str], key: &str) -> Option<usize> {
    let prefix = format!("{key}=");
    parts
        .iter()
        .find_map(|p| p.strip_prefix(&prefix)?.parse().ok())
}

pub fn kv_str<'a>(parts: &[&'a str], key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    parts.iter().find_map(|p| p.strip_prefix(&prefix))
}

/// Parse `JOB <tag> <blob> <tgt> <nstart> <nend> [gen=] [epoch=] [algo=] [nonce_bytes=]`.
pub fn parse_job(msg: &str) -> Option<Job> {
    let parts: Vec<&str> = msg.split_whitespace().collect();
    if parts.len() < 6 || parts[0] != "JOB" {
        return None;
    }
    let tag: u32 = parts[1].parse().ok()?;
    let blob = hex::decode(parts[2]).ok()?;
    let target = miner::parse_target(parts[3])?;
    let nstart = u32::from_str_radix(parts[4], 16).ok()?;
    let nend = u32::from_str_radix(parts[5], 16).ok()?;
    let gen = kv_u32(&parts, "gen").unwrap_or(0);
    let epoch = kv_u32(&parts, "epoch").unwrap_or(0);
    let algo = kv_str(&parts, "algo").unwrap_or("sha256d").to_string();
    if !algo_supported(&algo) {
        return None;
    }
    let nonce_bytes =
        kv_usize(&parts, "nonce_bytes").unwrap_or(if algo == "verushash" { 8 } else { 4 });

    let mut header = [0u8; 76];
    if algo == "sha256d" || algo.is_empty() {
        if blob.len() != 76 {
            return None;
        }
        header.copy_from_slice(&blob);
    } else if algo == "verushash" {
        if blob.len() < 140 {
            return None;
        }
    } else {
        return None;
    }

    Some(Job {
        tag,
        gen,
        epoch,
        algo,
        blob,
        header,
        target,
        nstart,
        nend,
        nonce_bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitResult {
    pub verdict: String,
    pub tag: Option<u32>,
    pub nonce: Option<u64>,
    pub sid: Option<u32>,
}

/// Parse `RESULT <verdict> [tag=] [nonce=] [sid=]`.
pub fn parse_result(msg: &str) -> Option<SubmitResult> {
    let rest = msg.strip_prefix("RESULT ")?;
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    let verdict = parts[0].to_string();
    let tag = kv_u32(&parts, "tag");
    let nonce = parts.iter().find_map(|p| {
        p.strip_prefix("nonce=")
            .and_then(|h| u64::from_str_radix(h, 16).ok())
    });
    let sid = kv_u32(&parts, "sid");
    Some(SubmitResult {
        verdict,
        tag,
        nonce,
        sid,
    })
}

/// Parse `CAPS ... epoch=<u> algo=<s>` (ok or reject).
pub fn parse_caps_epoch(msg: &str) -> Option<u32> {
    if !msg.starts_with("CAPS") {
        return None;
    }
    let parts: Vec<&str> = msg.split_whitespace().collect();
    kv_u32(&parts, "epoch")
}

pub fn parse_caps_algo(msg: &str) -> Option<String> {
    if !msg.starts_with("CAPS") {
        return None;
    }
    let parts: Vec<&str> = msg.split_whitespace().collect();
    kv_str(&parts, "algo").map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_legacy_and_extended() {
        let hdr = "00".repeat(76);
        let tgt = "ff".repeat(32);
        let legacy = format!("JOB 3 {hdr} {tgt} 00000000 ffffffff");
        let j = parse_job(&legacy).expect("legacy");
        assert_eq!(j.tag, 3);
        assert_eq!(j.gen, 0);
        assert_eq!(j.epoch, 0);
        assert_eq!(j.algo, "sha256d");
        assert_eq!(j.nonce_bytes, 4);

        let ext = format!("JOB 9 {hdr} {tgt} 00000000 ffffffff gen=42 epoch=7 algo=sha256d");
        let j2 = parse_job(&ext).expect("ext");
        assert_eq!(j2.tag, 9);
        assert_eq!(j2.gen, 42);
        assert_eq!(j2.epoch, 7);
        assert_eq!(j2.algo, "sha256d");
    }

    #[test]
    fn job_verushash_blob() {
        let blob = "00".repeat(140 + 8);
        let tgt = "ff".repeat(32);
        let msg = format!(
            "JOB 1 {blob} {tgt} 00000000 0000ffff gen=1 epoch=2 algo=verushash nonce_bytes=8"
        );
        let j = parse_job(&msg).expect("verus");
        assert_eq!(j.algo, "verushash");
        assert_eq!(j.nonce_bytes, 8);
        assert_eq!(j.blob.len(), 148);
    }

    #[test]
    fn job_rejects_unknown_algo() {
        let hdr = "00".repeat(76);
        let tgt = "ff".repeat(32);
        let msg = format!("JOB 1 {hdr} {tgt} 00000000 ffffffff algo=scrypt");
        assert!(parse_job(&msg).is_none());
    }

    #[test]
    fn result_correlated() {
        let r = parse_result("RESULT ok tag=3 nonce=00abcdef sid=9").unwrap();
        assert_eq!(r.verdict, "ok");
        assert_eq!(r.tag, Some(3));
        assert_eq!(r.nonce, Some(0x00abcdef));
        assert_eq!(r.sid, Some(9));

        let legacy = parse_result("RESULT stale").unwrap();
        assert_eq!(legacy.verdict, "stale");
        assert!(legacy.tag.is_none());
    }

    #[test]
    fn caps_epoch() {
        assert_eq!(
            parse_caps_epoch("CAPS ok ver=1 algo=sha256d epoch=12"),
            Some(12)
        );
        assert!(parse_caps_epoch("PING").is_none());
    }

    #[test]
    fn caps_reject_and_negotiate() {
        assert!(caps_is_reject("CAPS reject ver=1 algo=sha256d epoch=3"));
        assert!(!caps_is_reject("CAPS ok ver=1 algo=sha256d epoch=3"));
        assert!(negotiate_algo("sha256d").is_ok());
        assert!(negotiate_algo("verushash").is_ok());
        assert!(negotiate_algo("").is_ok());
        let err = negotiate_algo("scrypt").unwrap_err();
        assert!(err.contains("mismatch"));
    }
}
