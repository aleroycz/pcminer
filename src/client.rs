// SPDX-License-Identifier: GPL-3.0-or-later
//
// Background worker: discover phone, MMSHARE1 session, JOB sweep, FOUND upstream.
//
// Copyright (C) 2026 Vakea

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::app::{AppState, Phase};
use crate::config::Config;
use crate::discovery;
use crate::miner::{self, Job, MiningHandle};
use crate::net::{RecvOutcome, Session};
use crate::nvidia_perf::NvidiaPerfGuard;
use crate::proto::{self, SubmitResult};
use crate::thermal::{ThermalBand, ThermalGuard};

pub fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let my_pk = cfg.public_bytes();
    let my_sk = cfg.secret_bytes();
    // Leave one core for the TUI/OS when auto-sizing - saturating every core
    // freezes the dashboard while hashing still "works".
    let threads = if cfg.threads == 0 {
        num_cpus::get().saturating_sub(1).max(1)
    } else {
        cfg.threads.max(1)
    };
    let prefer_gpu = cfg.use_gpu;
    let unlock_gpu = cfg.unlock_gpu_perf && prefer_gpu;
    let thermal_cfg = cfg.thermal.sanitized();

    // Hold for process lifetime of the worker; restores clocks/PL on drop.
    let mut _gpu_perf = if unlock_gpu {
        let g = NvidiaPerfGuard::acquire();
        set(&state, |s| s.log(g.summary().to_string()));
        g
    } else {
        NvidiaPerfGuard::inactive()
    };

    loop {
        if quit(&state) {
            return;
        }

        // 1) Resolve the phone's address (fixed host, or UDP discovery).
        let target = match resolve_target(&state, &cfg) {
            Some(t) => t,
            None => {
                sleep_interruptible(&state, Duration::from_secs(3));
                continue;
            }
        };

        // 2) Connect + handshake.
        set(&state, |s| {
            s.set_phase(Phase::Connecting, format!("connecting to {target}"))
        });
        let sock = match TcpStream::connect_timeout(&target, Duration::from_secs(8)) {
            Ok(s) => s,
            Err(e) => {
                set(&state, |s| {
                    s.set_phase(Phase::Error, format!("connect failed: {e}"));
                    s.log(format!("connect to {target} failed: {e}"));
                });
                sleep_interruptible(&state, Duration::from_secs(4));
                continue;
            }
        };

        set(&state, |s| {
            s.set_phase(
                Phase::WaitingPair,
                "handshaking (confirm on phone if prompted)",
            )
        });
        let session = match Session::handshake(
            sock,
            &my_pk,
            &my_sk,
            &cfg.worker_name,
            Duration::from_secs(65),
        ) {
            Ok(sess) => sess,
            Err(e) => {
                set(&state, |s| {
                    s.set_phase(Phase::Error, format!("{e}"));
                    s.log(format!("handshake failed: {e}"));
                });
                sleep_interruptible(&state, Duration::from_secs(4));
                continue;
            }
        };

        let dev_name = session.device_name.clone();
        let dev_fp = fingerprint(&session.device_pk);
        set(&state, |s| {
            s.device_name = dev_name.clone();
            s.device_fp = dev_fp.clone();
            // Paired, but do not look "mining" until a JOB arrives (never auto-arm).
            s.armed = false;
            s.set_phase(Phase::Idle, "paired; waiting for job");
            s.log(format!("paired with {dev_name} [{dev_fp}]"));
        });

        // 3) Service the work loop until the link drops.
        work_loop(&state, session, threads, prefer_gpu, thermal_cfg.clone());

        if quit(&state) {
            return;
        }
        set(&state, |s| {
            s.armed = false;
            s.hashrate = 0.0;
            s.backend = "—".into();
            s.set_phase(Phase::Idle, "disconnected - retrying");
            s.log("link closed; reconnecting");
        });
        sleep_interruptible(&state, Duration::from_secs(2));
    }
}

fn work_loop(
    state: &Arc<Mutex<AppState>>,
    mut session: Session,
    threads: usize,
    prefer_gpu: bool,
    thermal_cfg: crate::config::ThermalConfig,
) {
    session.set_read_timeout(Some(Duration::from_millis(1000)));

    let (found_tx, found_rx) = mpsc::channel::<(u32, u64)>();
    let hashes = Arc::new(AtomicU64::new(0));
    let mut mining: Option<MiningHandle> = None;
    // Reconnect hygiene: refuse to hash until a JOB for this session; drain defensively even though
    // the channel is fresh.
    let mut cur_tag: u32 = 0;
    let mut cur_gen: u32 = 0;
    let mut session_epoch: u32 = 0; // 0 = unset (legacy phone / CAPS not yet seen)
    let mut have_job = false;
    let mut active_job: Option<Job> = None;
    let mut next_sid: u32 = 1;
    let mut pending_sid: Option<u32> = None;

    let mut cumulative: u64 = 0;
    let mut last_handle_hashes: u64 = 0;
    let mut last_rate_t = Instant::now();
    let mut last_stat = Instant::now();
    let mut paused_latch = false;
    let mut thermal_paused = false;
    let mut last_thermal_band = ThermalBand::Ok;
    let mut backpressure = false; // WAIT from phone: slow the poll loop
    let mut thermal = ThermalGuard::new(thermal_cfg);
    let mut using_gpu = false;

    flush_inflight(&mut mining, &found_rx, &hashes, &mut last_handle_hashes);

    // CAPS negotiates algo; phone offers active algo, we accept sha256d or verushash.
    let _ = session.send("CAPS ver=1 algo=sha256d");

    {
        let sample = thermal.tick(false);
        set(state, |s| {
            if thermal.enabled() && thermal.has_sensor() {
                s.log(format!(
                    "thermal guard on (NVIDIA) — pause when hot, power-cap when warm ({})",
                    sample.note
                ));
            } else if thermal.enabled() {
                s.log(sample.note);
            }
        });
    }

    loop {
        if quit(state) {
            let _ = session.send("BYE");
            flush_inflight(&mut mining, &found_rx, &hashes, &mut last_handle_hashes);
            thermal.restore();
            return;
        }

        // ---- thermal tick (safe pause / power-cap) ----------------------
        {
            let sample = thermal.tick(using_gpu || prefer_gpu);
            set(state, |s| {
                s.gpu_temp_c = sample.temp_c.unwrap_or(-1);
                s.gpu_fan_pct = sample.fan_pct.map(|v| v as i32).unwrap_or(-1);
                s.thermal_band = sample.band.label().into();
            });
            if sample.band != last_thermal_band {
                set(state, |s| s.log(sample.note.clone()));
                last_thermal_band = sample.band;
            }

            let want_thermal_pause = sample.band.must_pause();
            if want_thermal_pause && !thermal_paused {
                thermal_paused = true;
                mining = None;
                using_gpu = false;
                set(state, |s| {
                    s.hashrate = 0.0;
                    s.backend = "—".into();
                    s.set_phase(
                        Phase::Paused,
                        format!("thermal cool-down (GPU {}°C)", sample.temp_c.unwrap_or(-1)),
                    );
                });
            } else if !want_thermal_pause && thermal_paused {
                thermal_paused = false;
                // Resume the last job if the phone is still armed and operator isn't pausing.
                let op_pause = get(state, |s| s.want_pause);
                if !op_pause && have_job {
                    if let Some(job) = active_job.clone() {
                        set(state, |s| {
                            s.set_phase(Phase::Mining, "resumed after cool-down");
                            s.log("thermal clear — restarting sweep");
                        });
                        let handle =
                            start_backend(job, threads, prefer_gpu, &found_tx, &hashes, state);
                        using_gpu = get(state, |s| s.backend.starts_with('G'));
                        mining = Some(handle);
                    }
                } else {
                    set(state, |s| {
                        s.set_phase(
                            if s.armed { Phase::Idle } else { Phase::Idle },
                            "cooled; waiting for work",
                        );
                    });
                }
            }
        }

        let paused = get(state, |s| s.want_pause) || thermal_paused;
        if get(state, |s| s.want_pause) != paused_latch {
            paused_latch = get(state, |s| s.want_pause);
            if paused_latch {
                mining = None; // drop => cancel (join is async)
                using_gpu = false;
                set(state, |s| {
                    s.hashrate = 0.0;
                    s.backend = "—".into();
                    s.set_phase(Phase::Paused, "paused by operator");
                    s.log("mining paused");
                });
            } else if !thermal_paused {
                set(state, |s| {
                    s.set_phase(if s.armed { Phase::Mining } else { Phase::Idle }, "resumed");
                    s.log("mining resumed");
                });
                if have_job {
                    if let Some(job) = active_job.clone() {
                        let handle =
                            start_backend(job, threads, prefer_gpu, &found_tx, &hashes, state);
                        using_gpu = get(state, |s| s.backend.starts_with('G'));
                        mining = Some(handle);
                    }
                }
            }
        }

        // ---- receive one message (1s timeout; longer under WAIT) -------
        if backpressure {
            session.set_read_timeout(Some(Duration::from_millis(2500)));
        } else {
            session.set_read_timeout(Some(Duration::from_millis(1000)));
        }

        match session.recv() {
            Ok(RecvOutcome::Msg(msg)) => {
                if let Some(job) = proto::parse_job(&msg) {
                    if !accept_job(&job, session_epoch) {
                        set(state, |s| {
                            s.log(format!(
                                "dropping stale/foreign JOB tag={} gen={} epoch={} (session epoch {session_epoch})",
                                job.tag, job.gen, job.epoch
                            ));
                        });
                    } else {
                        if job.epoch != 0 {
                            session_epoch = job.epoch;
                        }
                        cur_tag = job.tag;
                        cur_gen = job.gen;
                        have_job = true;
                        active_job = Some(job.clone());
                        backpressure = false;
                        pending_sid = None;
                        // Cancel prior sweep before starting the new one.
                        flush_inflight(&mut mining, &found_rx, &hashes, &mut last_handle_hashes);
                        using_gpu = false;
                        let span = job.nend.saturating_sub(job.nstart).saturating_add(1);
                        // Merkle root @ header[36..44) - must differ per PC (unique extranonce2).
                        let merkle_fp = hex::encode(&job.header[36..44]);
                        set(state, |s| {
                            s.armed = true;
                            s.current_tag = job.tag;
                            if !matches!(s.phase, Phase::Paused) {
                                s.set_phase(Phase::Mining, format!("mining gen={}", job.gen));
                            }
                            s.log(format!(
                                "JOB tag={} gen={} merkle={}.. range={:08x}..{:08x} ({} nonces)",
                                job.tag, job.gen, merkle_fp, job.nstart, job.nend, span
                            ));
                        });
                        if !paused {
                            let handle =
                                start_backend(job, threads, prefer_gpu, &found_tx, &hashes, state);
                            using_gpu = get(state, |s| s.backend.starts_with('G'));
                            mining = Some(handle);
                        }
                    }
                } else if msg == "IDLE" {
                    have_job = false;
                    active_job = None;
                    backpressure = false;
                    pending_sid = None;
                    flush_inflight(&mut mining, &found_rx, &hashes, &mut last_handle_hashes);
                    using_gpu = false;
                    set(state, |s| {
                        s.armed = false;
                        s.hashrate = 0.0;
                        s.backend = "—".into();
                        if !matches!(s.phase, Phase::Paused) {
                            s.set_phase(Phase::Idle, "phone idle (miner disarmed)");
                        }
                    });
                } else if msg == "WAIT" {
                    // Armed on phone but no pool job: stop hashing, stay linked.
                    have_job = false;
                    active_job = None;
                    backpressure = true;
                    pending_sid = None;
                    flush_inflight(&mut mining, &found_rx, &hashes, &mut last_handle_hashes);
                    using_gpu = false;
                    set(state, |s| {
                        s.armed = false;
                        s.hashrate = 0.0;
                        s.backend = "—".into();
                        if !matches!(s.phase, Phase::Paused) {
                            s.set_phase(Phase::Idle, "waiting for pool job (backpressure)");
                        }
                        s.log("WAIT: phone has no pool job; hashing paused");
                    });
                } else if msg.starts_with("CAPS") {
                    if let Some(ep) = proto::parse_caps_epoch(&msg) {
                        session_epoch = ep;
                    }
                    if proto::caps_is_reject(&msg) {
                        set(state, |s| {
                            s.log(format!("CAPS rejected by phone: {msg}"));
                            s.set_phase(Phase::Error, "algo not accepted by phone");
                        });
                        flush_inflight(&mut mining, &found_rx, &hashes, &mut last_handle_hashes);
                        have_job = false;
                    } else if let Some(algo) = proto::parse_caps_algo(&msg) {
                        match proto::negotiate_algo(&algo) {
                            Ok(ok) => {
                                let _ = session.send(&format!("CAPS ver=1 algo={ok}"));
                                set(state, |s| {
                                    s.log(format!("CAPS ok algo={ok} epoch={session_epoch}"));
                                });
                            }
                            Err(why) => {
                                set(state, |s| {
                                    s.log(format!("CAPS mismatch: {why}"));
                                    s.set_phase(Phase::Error, why);
                                });
                                flush_inflight(
                                    &mut mining,
                                    &found_rx,
                                    &hashes,
                                    &mut last_handle_hashes,
                                );
                                have_job = false;
                            }
                        }
                    }
                } else if msg.starts_with("JOB ") {
                    // parse_job already returned None (algo / shape reject).
                    set(state, |s| {
                        s.log(format!(
                            "rejected JOB (unsupported algo or malformed): {}",
                            msg.chars().take(96).collect::<String>()
                        ));
                    });
                } else if msg == "PING" {
                    let _ = session.send("PONG");
                } else if msg == "PONG" {
                    // keepalive ack
                } else if let Some(rest) = msg.strip_prefix("RESULT ") {
                    // Prefer correlated parser; fall back to bare verdict.
                    if let Some(r) = proto::parse_result(&format!("RESULT {rest}")) {
                        apply_result(state, &r, &mut pending_sid);
                    } else {
                        record_verdict(state, rest.trim());
                    }
                }
            }
            Ok(RecvOutcome::Timeout) => { /* fall through to housekeeping */ }
            Err(e) => {
                set(state, |s| s.log(format!("recv error: {e}")));
                flush_inflight(&mut mining, &found_rx, &hashes, &mut last_handle_hashes);
                return;
            }
        }

        // ---- report any nonces the sweepers found ----------------------
        loop {
            match found_rx.try_recv() {
                Ok((tag, nonce)) => {
                    // Drop stale finds: wrong tag, or job already retracted.
                    if !(have_job && tag == cur_tag) {
                        continue;
                    }
                    let sid = next_sid;
                    next_sid = next_sid.wrapping_add(1).max(1);
                    let width = active_job
                        .as_ref()
                        .map(|j| j.nonce_bytes.max(4) * 2)
                        .unwrap_or(8);
                    let nhex = format!("{nonce:0width$x}", width = width);
                    let line = format!("FOUND {tag} {nhex} sid={sid}");
                    if session.send(&line).is_err() {
                        flush_inflight(&mut mining, &found_rx, &hashes, &mut last_handle_hashes);
                        return;
                    }
                    pending_sid = Some(sid);
                    set(state, |s| {
                        s.found += 1;
                        s.log(format!(
                            "found nonce {nhex} (tag {tag} gen {cur_gen} sid {sid}) -> phone"
                        ));
                    });
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        // ---- hashrate bookkeeping + range-exhausted -> DONE --------------
        if let Some(h) = &mining {
            let cur = h.hashes();
            let delta = cur.saturating_sub(last_handle_hashes);
            last_handle_hashes = cur;
            cumulative += delta;
            let dt = last_rate_t.elapsed().as_secs_f64();
            if dt >= 0.5 {
                let inst = delta as f64 / dt;
                last_rate_t = Instant::now();
                set(state, |s| {
                    s.hashrate = if s.hashrate <= 0.0 {
                        inst
                    } else {
                        s.hashrate * 0.6 + inst * 0.4
                    };
                    s.total_hashes = cumulative;
                });
            }
            // Sweep thread finished its nstart..nend pass (hash counter stopped
            // growing and joinable). Ask the phone for a fresh extranonce2 unit.
            if have_job && !paused && delta == 0 && cur > 0 && h.finished() {
                set(state, |s| {
                    s.log("nonce range exhausted — requesting new work")
                });
                let _ = session.send("DONE");
                flush_inflight(&mut mining, &found_rx, &hashes, &mut last_handle_hashes);
                using_gpu = false;
                // Keep have_job/active_job until phone sends the next JOB.
            }
        }

        // ---- periodic STAT to the phone --------------------------------
        if last_stat.elapsed() >= Duration::from_secs(5) {
            last_stat = Instant::now();
            let (th, rate) = get(state, |s| (s.total_hashes, s.hashrate));
            if session.send(&format!("STAT {th} {rate:.0}")).is_err() {
                flush_inflight(&mut mining, &found_rx, &hashes, &mut last_handle_hashes);
                return;
            }
        }
    }
}

/// Stop hashing and drain any in-flight FOUND notifications (reconnect / job change).
fn flush_inflight(
    mining: &mut Option<MiningHandle>,
    found_rx: &std::sync::mpsc::Receiver<(u32, u64)>,
    hashes: &Arc<AtomicU64>,
    last_handle_hashes: &mut u64,
) {
    *mining = None; // cancel + join
    while found_rx.try_recv().is_ok() {}
    hashes.store(0, Ordering::Relaxed);
    *last_handle_hashes = 0;
}

/// Accept a JOB only if its epoch matches this session (when both are set).
fn accept_job(job: &Job, session_epoch: u32) -> bool {
    if !proto::algo_supported(&job.algo) {
        return false;
    }
    // epoch 0 on either side = legacy / not yet negotiated -> accept.
    if job.epoch == 0 || session_epoch == 0 {
        return true;
    }
    job.epoch == session_epoch
}

/// Prefer GPU when requested + built + sha256d; Verus is CPU-only.
fn start_backend(
    job: Job,
    threads: usize,
    prefer_gpu: bool,
    found_tx: &Sender<(u32, u64)>,
    hashes: &Arc<AtomicU64>,
    state: &Arc<Mutex<AppState>>,
) -> MiningHandle {
    let gpu_ok = prefer_gpu && (job.algo.is_empty() || job.algo == "sha256d");
    if prefer_gpu && !gpu_ok {
        set(state, |s| {
            s.log(format!(
                "algo={} is CPU-only (OpenCL is sha256d-only)",
                job.algo
            ));
        });
    }
    #[cfg(feature = "gpu")]
    if gpu_ok {
        match crate::gpu::start(job.clone(), found_tx.clone(), hashes.clone()) {
            Ok(h) => {
                let label = crate::gpu::device_name().unwrap_or_else(|| "OpenCL GPU".into());
                set(state, |s| {
                    s.backend = "GPU".into();
                    s.log(format!("sweeping on GPU ({label})"));
                });
                return h;
            }
            Err(e) => {
                let detail = crate::gpu::last_error().unwrap_or_default();
                set(state, |s| {
                    if detail.is_empty() {
                        s.log(format!("GPU unavailable ({e}); using CPU"));
                    } else {
                        s.log(format!("GPU unavailable ({e} / {detail}); using CPU"));
                    }
                });
            }
        }
    }
    #[cfg(not(feature = "gpu"))]
    let _ = gpu_ok;

    set(state, |s| {
        s.backend = format!("CPU×{threads}");
        s.log(format!(
            "sweeping on CPU ({threads} threads) algo={}",
            job.algo
        ));
    });
    miner::start(job, threads, found_tx.clone(), hashes.clone())
}

fn apply_result(state: &Arc<Mutex<AppState>>, r: &SubmitResult, pending_sid: &mut Option<u32>) {
    if let (Some(ps), Some(sid)) = (*pending_sid, r.sid) {
        if ps == sid {
            *pending_sid = None;
        }
    }
    record_verdict(state, &r.verdict);
}

fn record_verdict(state: &Arc<Mutex<AppState>>, verdict: &str) {
    set(state, |s| match verdict {
        "ok" => {
            s.accepted += 1;
            // Phone ACK after local verify + submit attempt - pool reply is separate.
            s.log("share verified by phone (submitted to pool)");
        }
        "bad" => {
            s.rejected += 1;
            s.log("share rejected (bad target/nonce)");
        }
        "stale" => {
            s.stale += 1;
            s.log("share stale");
        }
        "nack" => {
            s.rejected += 1;
            s.log("share nack (duplicate or submit failed)");
        }
        other => s.log(format!("result: {other}")),
    });
}

fn resolve_target(state: &Arc<Mutex<AppState>>, cfg: &Config) -> Option<std::net::SocketAddr> {
    set(state, |s| s.want_rescan = false);

    // Fixed host skips discovery entirely (most reliable on Windows Wi-Fi).
    if let Some(host) = &cfg.host {
        set(state, |s| {
            s.set_phase(Phase::Connecting, format!("using fixed host {host}"))
        });
        return host
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .or_else(|| {
                set(state, |s| {
                    s.set_phase(Phase::Error, format!("bad --host value: {host}"));
                    s.log(format!("could not resolve host {host}"));
                });
                None
            });
    }

    set(state, |s| {
        s.set_phase(
            Phase::Discovering,
            "searching the LAN for the phone (Developer → Allow PC mining)",
        )
    });
    // Longer wait + subnet broadcasts; Windows often drops 255.255.255.255.
    match discovery::discover(cfg.port, Duration::from_millis(2500)) {
        Ok(offers) if !offers.is_empty() => {
            let chosen = offers[0].clone();
            set(state, |s| {
                if offers.len() > 1 {
                    s.log(format!(
                        "{} phones found; using {}",
                        offers.len(),
                        chosen.name
                    ));
                }
                s.set_phase(
                    Phase::Connecting,
                    format!("found {} at {}", chosen.name, chosen.addr),
                );
            });
            Some(chosen.addr)
        }
        Ok(_) => {
            set(state, |s| {
                s.set_phase(
                    Phase::Discovering,
                    "no phone found — enable Allow PC mining, or pass --host ip:48510",
                )
            });
            None
        }
        Err(e) => {
            set(state, |s| {
                s.set_phase(Phase::Error, format!("discovery error: {e}"));
                s.log(format!("discovery error: {e}"));
            });
            None
        }
    }
}

fn fingerprint(pk: &[u8; 32]) -> String {
    let h = hex::encode(pk);
    format!("{}..{}", &h[..6], &h[h.len() - 4..])
}

// ---- small shared-state helpers ----------------------------------------

fn set<F: FnOnce(&mut AppState)>(state: &Arc<Mutex<AppState>>, f: F) {
    if let Ok(mut s) = state.lock() {
        f(&mut s);
    }
}

fn get<T, F: FnOnce(&AppState) -> T>(state: &Arc<Mutex<AppState>>, f: F) -> T {
    let s = state.lock().unwrap();
    f(&s)
}

fn quit(state: &Arc<Mutex<AppState>>) -> bool {
    get(state, |s| s.want_quit)
}

/// Sleep in short slices so quit/rescan requests are honoured promptly.
fn sleep_interruptible(state: &Arc<Mutex<AppState>>, total: Duration) {
    let step = Duration::from_millis(150);
    let mut slept = Duration::ZERO;
    while slept < total {
        if get(state, |s| s.want_quit || s.want_rescan) {
            return;
        }
        std::thread::sleep(step);
        slept += step;
    }
}
