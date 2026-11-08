// SPDX-License-Identifier: GPL-3.0-or-later
//
// MicroMiner OS - PC share miner: worker orchestration state machine.
// Copyright (C) 2026 Vakea
//
// Runs on a background thread: find the phone, pair + handshake, then service
// the encrypted work loop - receive JOB units, sweep them on the CPU, and send
// FOUND nonces back for the phone to validate and submit. The phone is always
// the master; this side never talks to the pool and never sees the wallet.

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

pub fn run(state: Arc<Mutex<AppState>>, cfg: Config) {
    let my_pk = cfg.public_bytes();
    let my_sk = cfg.secret_bytes();
    let threads = if cfg.threads == 0 { num_cpus::get() } else { cfg.threads };

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
        set(&state, |s| s.set_phase(Phase::Connecting, format!("connecting to {target}")));
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

        set(&state, |s| s.set_phase(Phase::WaitingPair, "handshaking (confirm on phone if prompted)"));
        let session = match Session::handshake(sock, &my_pk, &my_sk, &cfg.worker_name, Duration::from_secs(65)) {
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
            s.set_phase(Phase::Mining, "connected");
            s.log(format!("paired with {dev_name} [{dev_fp}]"));
        });

        // 3) Service the work loop until the link drops.
        work_loop(&state, session, threads);

        if quit(&state) {
            return;
        }
        set(&state, |s| {
            s.armed = false;
            s.hashrate = 0.0;
            s.set_phase(Phase::Idle, "disconnected - retrying");
            s.log("link closed; reconnecting");
        });
        sleep_interruptible(&state, Duration::from_secs(2));
    }
}

fn work_loop(state: &Arc<Mutex<AppState>>, mut session: Session, threads: usize) {
    session.set_read_timeout(Some(Duration::from_millis(1000)));

    let (found_tx, found_rx) = mpsc::channel::<(u32, u32)>();
    let hashes = Arc::new(AtomicU64::new(0));
    let mut mining: Option<MiningHandle> = None;
    let mut cur_tag: u32 = 0;
    let mut have_job = false;

    let mut cumulative: u64 = 0;
    let mut last_handle_hashes: u64 = 0;
    let mut last_rate_t = Instant::now();
    let mut last_stat = Instant::now();
    let mut paused_latch = false;

    loop {
        if quit(state) {
            let _ = session.send("BYE");
            return;
        }

        let paused = get(state, |s| s.want_pause);
        if paused != paused_latch {
            paused_latch = paused;
            if paused {
                mining = None; // drop => cancel + join
                set(state, |s| {
                    s.hashrate = 0.0;
                    s.set_phase(Phase::Paused, "paused by operator");
                    s.log("mining paused");
                });
            } else {
                set(state, |s| {
                    s.set_phase(if s.armed { Phase::Mining } else { Phase::Idle }, "resumed");
                    s.log("mining resumed");
                });
                // A fresh JOB will restart the sweep; nothing to do here.
            }
        }

        // ---- receive one message (1s timeout) --------------------------
        match session.recv() {
            Ok(RecvOutcome::Msg(msg)) => {
                if let Some(job) = parse_job(&msg) {
                    cur_tag = job.tag;
                    have_job = true;
                    set(state, |s| {
                        s.armed = true;
                        s.current_tag = job.tag;
                        if !matches!(s.phase, Phase::Paused) {
                            s.set_phase(Phase::Mining, "mining");
                        }
                    });
                    if !paused {
                        // Replace the running sweep with the new unit.
                        last_handle_hashes = 0;
                        hashes.store(0, Ordering::Relaxed);
                        mining = Some(start_backend(job, threads, &found_tx, &hashes, state));
                    }
                } else if msg == "IDLE" {
                    have_job = false;
                    mining = None;
                    set(state, |s| {
                        s.armed = false;
                        s.hashrate = 0.0;
                        if !matches!(s.phase, Phase::Paused) {
                            s.set_phase(Phase::Idle, "phone idle (miner disarmed)");
                        }
                    });
                } else if msg == "PING" {
                    let _ = session.send("PONG");
                } else if msg == "PONG" {
                    // keepalive ack
                } else if let Some(rest) = msg.strip_prefix("RESULT ") {
                    record_result(state, rest.trim());
                }
            }
            Ok(RecvOutcome::Timeout) => { /* fall through to housekeeping */ }
            Err(e) => {
                set(state, |s| s.log(format!("recv error: {e}")));
                return;
            }
        }

        // ---- report any nonces the sweepers found ----------------------
        loop {
            match found_rx.try_recv() {
                Ok((tag, nonce)) => {
                    if have_job && tag == cur_tag {
                        if session.send(&format!("FOUND {tag} {nonce:08x}")).is_err() {
                            return;
                        }
                        set(state, |s| {
                            s.found += 1;
                            s.log(format!("found nonce {nonce:08x} (tag {tag}) -> phone"));
                        });
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        // ---- hashrate bookkeeping --------------------------------------
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
                    // Exponential smoothing for a steady readout.
                    s.hashrate = if s.hashrate <= 0.0 { inst } else { s.hashrate * 0.6 + inst * 0.4 };
                    s.total_hashes = cumulative;
                });
            }
        }

        // ---- periodic STAT to the phone --------------------------------
        if last_stat.elapsed() >= Duration::from_secs(5) {
            last_stat = Instant::now();
            let (th, rate) = get(state, |s| (s.total_hashes, s.hashrate));
            if session.send(&format!("STAT {th} {rate:.0}")).is_err() {
                return;
            }
        }
    }
}

/// Start a mining sweep for `job`. With the `gpu` feature we try the OpenCL
/// backend first and fall back to the CPU backend on any initialisation error.
fn start_backend(
    job: Job,
    threads: usize,
    found_tx: &Sender<(u32, u32)>,
    hashes: &Arc<AtomicU64>,
    state: &Arc<Mutex<AppState>>,
) -> MiningHandle {
    #[cfg(feature = "gpu")]
    {
        match crate::gpu::start(job.clone(), found_tx.clone(), hashes.clone()) {
            Ok(h) => {
                set(state, |s| s.log("sweeping on GPU (OpenCL)"));
                return h;
            }
            Err(e) => {
                set(state, |s| s.log(format!("GPU unavailable ({e}); using CPU")));
            }
        }
    }
    let _ = state;
    miner::start(job, threads, found_tx.clone(), hashes.clone())
}

fn record_result(state: &Arc<Mutex<AppState>>, verdict: &str) {
    set(state, |s| match verdict {
        "ok" => {
            s.accepted += 1;
            s.log("share accepted by pool");
        }
        "bad" => {
            s.rejected += 1;
            s.log("share rejected (bad)");
        }
        "stale" => {
            s.stale += 1;
            s.log("share stale");
        }
        other => s.log(format!("result: {other}")),
    });
}

/// Parse "JOB <tag> <header76hex> <targethex> <nstart> <nend>".
fn parse_job(msg: &str) -> Option<Job> {
    let mut it = msg.split_whitespace();
    if it.next()? != "JOB" {
        return None;
    }
    let tag: u32 = it.next()?.parse().ok()?;
    let hdr_hex = it.next()?;
    let tgt_hex = it.next()?;
    let nstart = u32::from_str_radix(it.next()?, 16).ok()?;
    let nend = u32::from_str_radix(it.next()?, 16).ok()?;

    let hdr_raw = hex::decode(hdr_hex).ok()?;
    if hdr_raw.len() != 76 {
        return None;
    }
    let mut header = [0u8; 76];
    header.copy_from_slice(&hdr_raw);
    let target = miner::parse_target(tgt_hex)?;
    Some(Job { tag, header, target, nstart, nend })
}

fn resolve_target(state: &Arc<Mutex<AppState>>, cfg: &Config) -> Option<std::net::SocketAddr> {
    set(state, |s| s.want_rescan = false);

    if let Some(host) = &cfg.host {
        set(state, |s| s.set_phase(Phase::Connecting, format!("using fixed host {host}")));
        return host.to_socket_addrs().ok().and_then(|mut a| a.next());
    }

    set(state, |s| s.set_phase(Phase::Discovering, "searching the LAN for the phone"));
    match discovery::discover(cfg.port, Duration::from_millis(1500)) {
        Ok(offers) if !offers.is_empty() => {
            let chosen = offers[0].clone();
            set(state, |s| {
                if offers.len() > 1 {
                    s.log(format!("{} phones found; using {}", offers.len(), chosen.name));
                }
                s.set_phase(Phase::Connecting, format!("found {} at {}", chosen.name, chosen.addr));
            });
            Some(chosen.addr)
        }
        Ok(_) => {
            set(state, |s| s.set_phase(Phase::Discovering, "no phone found yet - is sharing enabled on it?"));
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
