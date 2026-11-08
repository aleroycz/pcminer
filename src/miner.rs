// SPDX-License-Identifier: GPL-3.0-or-later
//
// MicroMiner OS - PC share miner: CPU sha256d nonce sweeper.
// Copyright (C) 2026 Vakea
//
// The phone hands out a work unit: a 76-byte header prefix, an 8-word target,
// and a nonce range. We sweep nonces across all CPU threads, double-SHA-256 the
// 80-byte header (prefix + 4-byte little-endian nonce), and compare the result
// to the target the same way the device does (hash interpreted as 8 LE u32
// words, most-significant word first). Any nonce that meets the target is
// reported back; the phone re-validates and submits it to the pool.

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;

/// One unit of work from the phone.
#[derive(Clone)]
pub struct Job {
    pub tag: u32,
    pub header: [u8; 76],
    pub target: [u32; 8],
    pub nstart: u32,
    pub nend: u32,
}

/// A running sweep. Dropping it (or calling `cancel`) stops all worker threads.
pub struct MiningHandle {
    cancel: Arc<AtomicBool>,
    hashes: Arc<AtomicU64>,
    threads: Vec<JoinHandle<()>>,
}

impl MiningHandle {
    /// Build a handle from an already-spawned driver thread (used by the GPU
    /// backend, which runs a single dispatch loop rather than N CPU sweepers).
    #[allow(dead_code)] // only used with the `gpu` feature
    pub fn from_parts(cancel: Arc<AtomicBool>, hashes: Arc<AtomicU64>, threads: Vec<JoinHandle<()>>) -> Self {
        MiningHandle { cancel, hashes, threads }
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Total nonces hashed so far across all threads.
    pub fn hashes(&self) -> u64 {
        self.hashes.load(Ordering::Relaxed)
    }
}

impl Drop for MiningHandle {
    fn drop(&mut self) {
        self.cancel();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

const CHUNK: u64 = 8192;

/// Spawn `nthreads` workers sweeping the job's nonce range. Found nonces are
/// sent on `found`. The shared `hashes` counter lets the UI compute a hashrate.
pub fn start(job: Job, nthreads: usize, found: Sender<(u32, u32)>, hashes: Arc<AtomicU64>) -> MiningHandle {
    let cancel = Arc::new(AtomicBool::new(false));
    let cursor = Arc::new(AtomicU64::new(job.nstart as u64));
    let end = job.nend as u64;
    let nthreads = nthreads.max(1);

    let mut threads = Vec::with_capacity(nthreads);
    for _ in 0..nthreads {
        let cancel = cancel.clone();
        let cursor = cursor.clone();
        let hashes = hashes.clone();
        let found = found.clone();
        let job = job.clone();
        threads.push(std::thread::spawn(move || {
            let mut header = [0u8; 80];
            header[..76].copy_from_slice(&job.header);
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                let base = cursor.fetch_add(CHUNK, Ordering::Relaxed);
                if base > end {
                    return;
                }
                let last = (base + CHUNK - 1).min(end);
                let mut local = 0u64;
                for nonce in base..=last {
                    let n = nonce as u32;
                    header[76] = n as u8;
                    header[77] = (n >> 8) as u8;
                    header[78] = (n >> 16) as u8;
                    header[79] = (n >> 24) as u8;
                    if meets_target(&sha256d(&header), &job.target) {
                        let _ = found.send((job.tag, n));
                    }
                    local += 1;
                }
                hashes.fetch_add(local, Ordering::Relaxed);
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
            }
        }));
    }

    MiningHandle { cancel, hashes, threads }
}

#[inline]
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// True if `hash` <= `target`, matching the device's hash_le_target(): the
/// 32-byte hash is read as 8 little-endian u32 words and compared from the
/// most-significant word (index 7) down.
#[inline]
pub fn meets_target(hash: &[u8; 32], target: &[u32; 8]) -> bool {
    for i in (0..8).rev() {
        let hw = u32::from_le_bytes([
            hash[4 * i],
            hash[4 * i + 1],
            hash[4 * i + 2],
            hash[4 * i + 3],
        ]);
        if hw < target[i] {
            return true;
        }
        if hw > target[i] {
            return false;
        }
    }
    true
}

/// Parse a 32-byte target (hex) into 8 little-endian u32 words, matching the
/// device's target_hex() serialization.
pub fn parse_target(hexstr: &str) -> Option<[u32; 8]> {
    let raw = hex::decode(hexstr).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut t = [0u32; 8];
    for k in 0..8 {
        t[k] = u32::from_le_bytes([raw[4 * k], raw[4 * k + 1], raw[4 * k + 2], raw[4 * k + 3]]);
    }
    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bitcoin genesis block 80-byte header hashes (sha256d) to the well-known
    // value ...000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000
    // (little-endian display), confirming our double hash is correct.
    #[test]
    fn genesis_sha256d() {
        let header = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c",
        )
        .unwrap();
        let h = sha256d(&header);
        // Internal (little-endian) byte order of the genesis hash.
        let expect =
            hex::decode("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")
                .unwrap();
        assert_eq!(&h[..], &expect[..]);
    }

    #[test]
    fn target_compare() {
        // All-ones target => every hash meets it.
        let t = [0xffffffffu32; 8];
        assert!(meets_target(&[0xff; 32], &t));
        // All-zero target => only the zero hash meets it.
        let z = [0u32; 8];
        assert!(!meets_target(&[1; 32], &z));
        assert!(meets_target(&[0; 32], &z));
    }
}
