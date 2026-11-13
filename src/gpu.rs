// SPDX-License-Identifier: GPL-3.0-or-later
//
// OpenCL sha256d sweep with midstate + cached program binary.
// Init/dispatch errors fall back to CPU.
//
// Copyright (C) 2026 Vakea

#![allow(deprecated)]

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock};

use opencl3::command_queue::CommandQueue;
use opencl3::context::Context;
use opencl3::device::{cl_device_id, get_all_devices, Device, CL_DEVICE_TYPE_GPU};
use opencl3::kernel::{ExecuteKernel, Kernel};
use opencl3::memory::{Buffer, CL_MEM_READ_ONLY, CL_MEM_READ_WRITE};
use opencl3::program::Program;
use opencl3::types::{cl_uint, CL_BLOCKING};
use std::ptr;

use crate::miner::{meets_target, sha256d, Job, MiningHandle};

const KERNEL_SRC: &str = include_str!("sha256d.cl");

/// Nonces per kernel launch - large enough to keep the GPU busy.
const BATCH: u32 = 1 << 24; // 16M
const MAX_FOUND: usize = 256;

struct ClCache {
    device_key: usize,
    name: String,
    /// Device binary from the first source build (fast path on later jobs).
    binary: Vec<u8>,
}

static CACHE: OnceLock<Result<ClCache, String>> = OnceLock::new();
static LAST_ERR: Mutex<Option<String>> = Mutex::new(None);

fn set_err(msg: impl Into<String>) {
    if let Ok(mut g) = LAST_ERR.lock() {
        *g = Some(msg.into());
    }
}

pub fn last_error() -> Option<String> {
    LAST_ERR.lock().ok().and_then(|g| g.clone())
}

fn cache() -> Result<&'static ClCache> {
    let slot = CACHE.get_or_init(|| {
        let device_ids = get_all_devices(CL_DEVICE_TYPE_GPU)
            .map_err(|e| format!("no OpenCL GPU devices: {e:?}"))?;
        let device_id = *device_ids
            .first()
            .ok_or_else(|| "no OpenCL GPU devices found".to_string())?;
        let device = Device::new(device_id);
        let name = device.name().unwrap_or_else(|_| "OpenCL GPU".to_string());
        let context = Context::from_device(&device).map_err(|e| format!("cl context: {e:?}"))?;
        let program = Program::create_and_build_from_source(&context, KERNEL_SRC, "")
            .map_err(|e| format!("cl program build failed: {e}"))?;
        let _ = Kernel::create(&program, "search").map_err(|e| format!("cl kernel: {e:?}"))?;
        let bins = program
            .get_binaries()
            .map_err(|e| format!("cl get_binaries: {e:?}"))?;
        let binary = bins
            .into_iter()
            .next()
            .filter(|b| !b.is_empty())
            .ok_or_else(|| "cl empty program binary".to_string())?;

        if let Err(e) = run_selftest(device_id as usize, &binary) {
            return Err(format!("OpenCL sha256d self-test failed: {e}"));
        }

        Ok(ClCache {
            device_key: device_id as usize,
            name,
            binary,
        })
    });
    match slot {
        Ok(c) => Ok(c),
        Err(msg) => Err(anyhow!("{msg}")),
    }
}

pub fn device_name() -> Option<String> {
    cache().ok().map(|c| c.name.clone())
}

/// Known-answer: genesis header nonce must meet an all-ones target and match CPU hash.
fn run_selftest(device_key: usize, binary: &[u8]) -> Result<()> {
    // Genesis block header (80 bytes) - CPU path already vectors this.
    let header = hex::decode(
        "0100000000000000000000000000000000000000000000000000000000000000\
         000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
         4b1e5e4a29ab5f49ffff001d1dac2b7c",
    )
    .map_err(|e| anyhow!("hex: {e}"))?;
    let mut prefix = [0u8; 76];
    prefix.copy_from_slice(&header[..76]);
    let nonce = u32::from_le_bytes([header[76], header[77], header[78], header[79]]);
    let target = [0xffffffffu32; 8];

    let cpu = sha256d(&header);
    if !meets_target(&cpu, &target) {
        return Err(anyhow!("CPU self-test precondition failed"));
    }

    let (found_tx, found_rx) = std::sync::mpsc::channel();
    let hashes = Arc::new(AtomicU64::new(0));
    let job = Job {
        tag: 0,
        gen: 0,
        epoch: 0,
        algo: "sha256d".into(),
        blob: prefix.to_vec(),
        header: prefix,
        target,
        nstart: nonce,
        nend: nonce,
        nonce_bytes: 4,
    };
    drive_with_binary(
        &job,
        &found_tx,
        &hashes,
        &AtomicBool::new(false),
        device_key,
        binary,
    )?;
    let got = found_rx
        .try_recv()
        .map_err(|_| anyhow!("GPU self-test found no nonce"))?;
    if got.1 != u64::from(nonce) {
        return Err(anyhow!("GPU self-test nonce mismatch"));
    }
    Ok(())
}

pub fn start(job: Job, found: Sender<(u32, u64)>, hashes: Arc<AtomicU64>) -> Result<MiningHandle> {
    if job.algo != "sha256d" && !job.algo.is_empty() {
        return Err(anyhow!(
            "OpenCL backend is sha256d-only (algo={})",
            job.algo
        ));
    }
    let eng = cache()?;
    let device_key = eng.device_key;
    let binary = eng.binary.clone();

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_t = cancel.clone();
    let hashes_t = hashes.clone();

    let handle = std::thread::Builder::new()
        .name("gpu-sweep".into())
        .spawn(move || {
            if let Err(e) =
                drive_with_binary(&job, &found, &hashes_t, &cancel_t, device_key, &binary)
            {
                set_err(format!("GPU sweep stopped: {e}"));
            }
        })
        .map_err(|e| anyhow!("spawn gpu thread: {e}"))?;

    Ok(MiningHandle::from_parts(cancel, hashes, vec![handle]))
}

/// Host midstate over header[0..64] + BE tail words for bytes 64..75.
fn midstate_and_tail(header76: &[u8; 76]) -> ([u32; 8], [u32; 3]) {
    let mut block = [0u32; 16];
    for i in 0..16 {
        let o = 4 * i;
        block[i] = u32::from_be_bytes([
            header76[o],
            header76[o + 1],
            header76[o + 2],
            header76[o + 3],
        ]);
    }
    let mut state = SHA_IV;
    sha256_transform(&mut state, &block);

    let mut tail = [0u32; 3];
    for i in 0..3 {
        let o = 64 + 4 * i;
        tail[i] = u32::from_be_bytes([
            header76[o],
            header76[o + 1],
            header76[o + 2],
            header76[o + 3],
        ]);
    }
    (state, tail)
}

const SHA_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn sha256_transform(state: &mut [u32; 8], block: &[u32; 16]) {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    fn rotr(x: u32, n: u32) -> u32 {
        x.rotate_right(n)
    }
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(block);
    for i in 16..64 {
        let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );
    for i in 0..64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn drive_with_binary(
    job: &Job,
    found: &Sender<(u32, u64)>,
    hashes: &Arc<AtomicU64>,
    cancel: &AtomicBool,
    device_key: usize,
    binary: &[u8],
) -> Result<()> {
    let device = Device::new(device_key as cl_device_id);
    let context = Context::from_device(&device).map_err(|e| anyhow!("cl context: {e:?}"))?;
    let queue =
        CommandQueue::create_default(&context, 0).map_err(|e| anyhow!("cl queue: {e:?}"))?;
    let mut program = unsafe {
        Program::create_from_binary(&context, &[device.id()], &[binary])
            .map_err(|e| anyhow!("cl binary program: {e:?}"))?
    };
    program
        .build(&[device.id()], "")
        .map_err(|e| anyhow!("cl binary build: {e}"))?;
    let kernel = Kernel::create(&program, "search").map_err(|e| anyhow!("cl kernel: {e:?}"))?;

    let (mid, tail) = midstate_and_tail(&job.header);

    let mut mid_buf = unsafe {
        Buffer::<cl_uint>::create(&context, CL_MEM_READ_ONLY, 8, ptr::null_mut())
            .map_err(|e| anyhow!("mid buf: {e:?}"))?
    };
    let mut tail_buf = unsafe {
        Buffer::<cl_uint>::create(&context, CL_MEM_READ_ONLY, 3, ptr::null_mut())
            .map_err(|e| anyhow!("tail buf: {e:?}"))?
    };
    let mut tgt_buf = unsafe {
        Buffer::<cl_uint>::create(&context, CL_MEM_READ_ONLY, 8, ptr::null_mut())
            .map_err(|e| anyhow!("tgt buf: {e:?}"))?
    };
    let mut out_buf = unsafe {
        Buffer::<cl_uint>::create(&context, CL_MEM_READ_WRITE, MAX_FOUND + 1, ptr::null_mut())
            .map_err(|e| anyhow!("out buf: {e:?}"))?
    };

    unsafe {
        queue
            .enqueue_write_buffer(&mut mid_buf, CL_BLOCKING, 0, &mid, &[])
            .map_err(|e| anyhow!("write mid: {e:?}"))?;
        queue
            .enqueue_write_buffer(&mut tail_buf, CL_BLOCKING, 0, &tail, &[])
            .map_err(|e| anyhow!("write tail: {e:?}"))?;
        queue
            .enqueue_write_buffer(&mut tgt_buf, CL_BLOCKING, 0, &job.target, &[])
            .map_err(|e| anyhow!("write tgt: {e:?}"))?;
    }

    let mut nonce = job.nstart as u64;
    let end = job.nend as u64;

    while nonce <= end {
        if cancel.load(Ordering::Relaxed) {
            return Ok(());
        }
        let this_batch = ((end - nonce + 1).min(BATCH as u64)) as u32;

        let zero = [0u32; 1];
        unsafe {
            queue
                .enqueue_write_buffer(&mut out_buf, CL_BLOCKING, 0, &zero, &[])
                .map_err(|e| anyhow!("reset out: {e:?}"))?;
        }

        let nstart = nonce as cl_uint;
        unsafe {
            ExecuteKernel::new(&kernel)
                .set_arg(&mid_buf)
                .set_arg(&tail_buf)
                .set_arg(&tgt_buf)
                .set_arg(&nstart)
                .set_arg(&mut out_buf)
                .set_global_work_size(this_batch as usize)
                .enqueue_nd_range(&queue)
                .map_err(|e| anyhow!("enqueue: {e:?}"))?;
        }

        let mut results = [0u32; MAX_FOUND + 1];
        unsafe {
            queue
                .enqueue_read_buffer(&out_buf, CL_BLOCKING, 0, &mut results, &[])
                .map_err(|e| anyhow!("read out: {e:?}"))?;
        }

        if cancel.load(Ordering::Relaxed) {
            return Ok(());
        }

        let count = (results[0] as usize).min(MAX_FOUND);
        for &n in results.iter().skip(1).take(count) {
            let _ = found.send((job.tag, u64::from(n)));
        }

        hashes.fetch_add(this_batch as u64, Ordering::Relaxed);
        nonce += this_batch as u64;
    }
    Ok(())
}
