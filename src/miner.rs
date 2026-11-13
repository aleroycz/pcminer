// SPDX-License-Identifier: GPL-3.0-or-later
//
// CPU nonce sweeper: sha256d (header) and verushash (blob + FFI).
//
// Copyright (C) 2026 Vakea

use sha2::{Digest, Sha256};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;

extern "C" {
    fn mm_verus_hash_init();
    fn mm_verus_hash_work(out: *mut u8, blob: *const u8, blob_len: usize, nonce: u64) -> c_int;
}

/// Phone JOB fields: tag/gen/epoch/algo, blob (76-byte hdr or Verus), LE target, range.
#[derive(Clone)]
pub struct Job {
    pub tag: u32,
    pub gen: u32,
    pub epoch: u32,
    pub algo: String,
    pub blob: Vec<u8>,
    pub header: [u8; 76],
    pub target: [u32; 8],
    pub nstart: u32,
    pub nend: u32,
    pub nonce_bytes: usize,
}

/// A running sweep. Dropping it (or calling `cancel`) stops all worker threads.
pub struct MiningHandle {
    cancel: Arc<AtomicBool>,
    hashes: Arc<AtomicU64>,
    threads: Vec<JoinHandle<()>>,
}

impl MiningHandle {
    #[allow(dead_code)] // only used with the `gpu` feature
    pub fn from_parts(
        cancel: Arc<AtomicBool>,
        hashes: Arc<AtomicU64>,
        threads: Vec<JoinHandle<()>>,
    ) -> Self {
        MiningHandle {
            cancel,
            hashes,
            threads,
        }
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn hashes(&self) -> u64 {
        self.hashes.load(Ordering::Relaxed)
    }

    pub fn finished(&self) -> bool {
        !self.threads.is_empty() && self.threads.iter().all(|t| t.is_finished())
    }
}

impl Drop for MiningHandle {
    fn drop(&mut self) {
        self.cancel();
        let leftover = std::mem::take(&mut self.threads);
        if leftover.is_empty() {
            return;
        }
        let _ = std::thread::Builder::new()
            .name("sweep-join".into())
            .spawn(move || {
                for t in leftover {
                    let _ = t.join();
                }
            });
    }
}

const CHUNK: u64 = 2048;

fn verus_init_once() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe { mm_verus_hash_init() });
}

/// Start `nthreads` CPU sweeps; hits go on `found` as (tag, nonce64).
pub fn start(
    job: Job,
    nthreads: usize,
    found: Sender<(u32, u64)>,
    hashes: Arc<AtomicU64>,
) -> MiningHandle {
    if job.algo == "verushash" {
        verus_init_once();
        return start_verus(job, nthreads, found, hashes);
    }
    start_sha256d(job, nthreads, found, hashes)
}

fn start_sha256d(
    job: Job,
    nthreads: usize,
    found: Sender<(u32, u64)>,
    hashes: Arc<AtomicU64>,
) -> MiningHandle {
    let cancel = Arc::new(AtomicBool::new(false));
    let cursor = Arc::new(AtomicU64::new(job.nstart as u64));
    let end = job.nend as u64;
    let nthreads = nthreads.max(1);

    let mut threads = Vec::with_capacity(nthreads);
    for i in 0..nthreads {
        let cancel = cancel.clone();
        let cursor = cursor.clone();
        let hashes = hashes.clone();
        let found = found.clone();
        let job = job.clone();
        let name = format!("cpu-sweep-{i}");
        threads.push(
            std::thread::Builder::new()
                .name(name)
                .spawn(move || {
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
                            if (local & 0xff) == 0 && cancel.load(Ordering::Relaxed) {
                                hashes.fetch_add(local, Ordering::Relaxed);
                                return;
                            }
                            let n = nonce as u32;
                            header[76] = n as u8;
                            header[77] = (n >> 8) as u8;
                            header[78] = (n >> 16) as u8;
                            header[79] = (n >> 24) as u8;
                            if meets_target(&sha256d(&header), &job.target) {
                                let _ = found.send((job.tag, nonce));
                            }
                            local += 1;
                        }
                        hashes.fetch_add(local, Ordering::Relaxed);
                    }
                })
                .expect("spawn cpu-sweep"),
        );
    }

    MiningHandle {
        cancel,
        hashes,
        threads,
    }
}

fn start_verus(
    job: Job,
    nthreads: usize,
    found: Sender<(u32, u64)>,
    hashes: Arc<AtomicU64>,
) -> MiningHandle {
    let cancel = Arc::new(AtomicBool::new(false));
    let cursor = Arc::new(AtomicU64::new(job.nstart as u64));
    let end = job.nend as u64;
    let nthreads = nthreads.max(1);

    let mut threads = Vec::with_capacity(nthreads);
    for i in 0..nthreads {
        let cancel = cancel.clone();
        let cursor = cursor.clone();
        let hashes = hashes.clone();
        let found = found.clone();
        let job = job.clone();
        let name = format!("verus-sweep-{i}");
        threads.push(
            std::thread::Builder::new()
                .name(name)
                .spawn(move || {
                    let mut out = [0u8; 32];
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
                            if (local & 0xff) == 0 && cancel.load(Ordering::Relaxed) {
                                hashes.fetch_add(local, Ordering::Relaxed);
                                return;
                            }
                            let rc = unsafe {
                                mm_verus_hash_work(
                                    out.as_mut_ptr(),
                                    job.blob.as_ptr(),
                                    job.blob.len(),
                                    nonce,
                                )
                            };
                            if rc == 0 && meets_target(&out, &job.target) {
                                let _ = found.send((job.tag, nonce));
                            }
                            local += 1;
                        }
                        hashes.fetch_add(local, Ordering::Relaxed);
                    }
                })
                .expect("spawn verus-sweep"),
        );
    }

    MiningHandle {
        cancel,
        hashes,
        threads,
    }
}

#[inline]
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

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

    #[test]
    fn genesis_sha256d() {
        let header = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c",
        )
        .unwrap();
        let h = sha256d(&header);
        let expect =
            hex::decode("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")
                .unwrap();
        assert_eq!(&h[..], &expect[..]);
    }

    #[test]
    fn target_compare() {
        let t = [0xffffffffu32; 8];
        assert!(meets_target(&[0xff; 32], &t));
        let z = [0u32; 8];
        assert!(!meets_target(&[1; 32], &z));
        assert!(meets_target(&[0; 32], &z));
    }
}
