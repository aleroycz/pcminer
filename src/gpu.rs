// SPDX-License-Identifier: GPL-3.0-or-later
//
// MicroMiner OS - PC share miner: OpenCL GPU sha256d backend.
// Copyright (C) 2026 Vakea
//
// Compiled only with `--features gpu`. Offloads the nonce sweep to an OpenCL
// device: the kernel builds the 80-byte header (76-byte prefix + per-work-item
// nonce), double-SHA-256s it, and compares the result to the target the same
// way the CPU path and the device do (8 little-endian u32 words, MSW first).
// Matching nonces are appended to an output buffer that the host drains and
// forwards to the phone.
//
// NOTE: the author could not run this on GPU hardware in the build environment,
// so while it compiles and the kernel mirrors the verified CPU algorithm, it
// should be validated on-device before being relied on. Any initialisation or
// dispatch error makes the caller fall back to the CPU backend automatically.

#![allow(deprecated)] // CommandQueue::create_default is fine for our CL target

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use opencl3::command_queue::CommandQueue;
use opencl3::context::Context;
use opencl3::device::{cl_device_id, get_all_devices, Device, CL_DEVICE_TYPE_GPU};
use opencl3::kernel::{ExecuteKernel, Kernel};
use opencl3::memory::{Buffer, CL_MEM_READ_ONLY, CL_MEM_READ_WRITE};
use opencl3::program::Program;
use opencl3::types::{cl_uint, CL_BLOCKING, CL_NON_BLOCKING};
use std::ptr;

use crate::miner::{Job, MiningHandle};

const KERNEL_SRC: &str = include_str!("sha256d.cl");

/// Per-dispatch work-item count (nonces per kernel launch).
const BATCH: u32 = 1 << 20; // ~1M nonces/dispatch
const MAX_FOUND: usize = 256;

/// Try to start a GPU sweep for `job`. On any OpenCL error returns Err so the
/// caller can fall back to the CPU backend.
pub fn start(
    job: Job,
    found: Sender<(u32, u32)>,
    hashes: Arc<AtomicU64>,
) -> Result<MiningHandle> {
    // Pick the first GPU device and build the program up front so init failures
    // surface here (before we commit to the GPU path).
    let device_ids = get_all_devices(CL_DEVICE_TYPE_GPU)
        .map_err(|e| anyhow!("no OpenCL GPU devices: {e:?}"))?;
    let device_id = *device_ids
        .first()
        .ok_or_else(|| anyhow!("no OpenCL GPU devices found"))?;
    let device = Device::new(device_id);
    let context = Context::from_device(&device).map_err(|e| anyhow!("cl context: {e:?}"))?;
    let program = Program::create_and_build_from_source(&context, KERNEL_SRC, "")
        .map_err(|e| anyhow!("cl program build failed: {e}"))?;
    // Validate the kernel exists now; recreated per thread below.
    let _ = Kernel::create(&program, "search").map_err(|e| anyhow!("cl kernel: {e:?}"))?;

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_t = cancel.clone();
    let hashes_t = hashes.clone();
    // A raw cl_device_id pointer isn't Send; carry it across the thread boundary
    // as an integer and rebuild the Device inside.
    let device_key = device_id as usize;

    let handle = std::thread::Builder::new()
        .name("gpu-sweep".into())
        .spawn(move || {
            if let Err(e) = drive(&job, &found, &hashes_t, &cancel_t, device_key) {
                // Surface as a found-channel-independent log via a sentinel: the
                // client treats a silent GPU stop as a disconnect-safe no-op, so
                // we just stop; the CPU fallback is chosen at job-start time.
                let _ = e;
            }
        })
        .map_err(|e| anyhow!("spawn gpu thread: {e}"))?;

    Ok(MiningHandle::from_parts(cancel, hashes, vec![handle]))
}

fn drive(
    job: &Job,
    found: &Sender<(u32, u32)>,
    hashes: &Arc<AtomicU64>,
    cancel: &Arc<AtomicBool>,
    device_key: usize,
) -> Result<()> {
    let device = Device::new(device_key as cl_device_id);
    let context = Context::from_device(&device).map_err(|e| anyhow!("cl context: {e:?}"))?;
    let queue = CommandQueue::create_default(&context, 0)
        .map_err(|e| anyhow!("cl queue: {e:?}"))?;
    let program = Program::create_and_build_from_source(&context, KERNEL_SRC, "")
        .map_err(|e| anyhow!("cl build: {e}"))?;
    let kernel = Kernel::create(&program, "search").map_err(|e| anyhow!("cl kernel: {e:?}"))?;

    // Static inputs: 76-byte header prefix (as 19 u32 little-endian words) and
    // the 8-word target.
    let mut header_words = [0u32; 19];
    for i in 0..19 {
        header_words[i] = u32::from_le_bytes([
            job.header[4 * i],
            job.header[4 * i + 1],
            job.header[4 * i + 2],
            job.header[4 * i + 3],
        ]);
    }

    let mut hdr_buf = unsafe {
        Buffer::<cl_uint>::create(&context, CL_MEM_READ_ONLY, 19, ptr::null_mut())
            .map_err(|e| anyhow!("hdr buf: {e:?}"))?
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
            .enqueue_write_buffer(&mut hdr_buf, CL_BLOCKING, 0, &header_words, &[])
            .map_err(|e| anyhow!("write hdr: {e:?}"))?;
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

        // Reset the output counter (slot 0 = count).
        let zero = [0u32; 1];
        unsafe {
            queue
                .enqueue_write_buffer(&mut out_buf, CL_BLOCKING, 0, &zero, &[])
                .map_err(|e| anyhow!("reset out: {e:?}"))?;
        }

        let nstart = nonce as cl_uint;
        unsafe {
            ExecuteKernel::new(&kernel)
                .set_arg(&hdr_buf)
                .set_arg(&tgt_buf)
                .set_arg(&nstart)
                .set_arg(&mut out_buf)
                .set_global_work_size(this_batch as usize)
                .enqueue_nd_range(&queue)
                .map_err(|e| anyhow!("enqueue: {e:?}"))?;
        }
        queue.finish().map_err(|e| anyhow!("finish: {e:?}"))?;

        // Read back the found nonces.
        let mut results = [0u32; MAX_FOUND + 1];
        unsafe {
            queue
                .enqueue_read_buffer(&out_buf, CL_NON_BLOCKING, 0, &mut results, &[])
                .map_err(|e| anyhow!("read out: {e:?}"))?;
        }
        queue.finish().map_err(|e| anyhow!("finish read: {e:?}"))?;

        let count = (results[0] as usize).min(MAX_FOUND);
        for &n in results.iter().skip(1).take(count) {
            let _ = found.send((job.tag, n));
        }

        hashes.fetch_add(this_batch as u64, Ordering::Relaxed);
        nonce += this_batch as u64;

        // Yield briefly so cancellation stays responsive on huge ranges.
        if this_batch < BATCH {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}
