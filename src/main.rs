// SPDX-License-Identifier: GPL-3.0-or-later
//
// MicroMiner OS - PC share miner.
// Copyright (C) 2026 Vakea
//
// Lends this PC's hashing power to a paired phone over the LAN. The phone is
// always the master: it owns the pool connection and the wallet, validates
// every nonce, and submits every share. This tool only sweeps nonce ranges the
// phone hands out. Run it, confirm the pairing on the phone the first time, and
// it mines whatever the phone is working on - and only while the phone's miner
// is armed.

mod app;
mod client;
mod config;
mod discovery;
#[cfg(feature = "gpu")]
mod gpu;
mod miner;
mod nacl;
mod net;
mod ui;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use std::io::stdout;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use app::AppState;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = config::load_or_init()?;
    let mut headless = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "--print-id" => {
                println!("worker public key: {}", cfg.public_hex());
                println!("config file:       {}", config::config_path().display());
                return Ok(());
            }
            "--host" => {
                i += 1;
                cfg.host = args.get(i).cloned();
            }
            "--name" => {
                i += 1;
                if let Some(n) = args.get(i) {
                    cfg.worker_name = n.clone();
                }
            }
            "--threads" => {
                i += 1;
                if let Some(n) = args.get(i).and_then(|v| v.parse::<usize>().ok()) {
                    cfg.threads = n;
                }
            }
            "--port" => {
                i += 1;
                if let Some(p) = args.get(i).and_then(|v| v.parse::<u16>().ok()) {
                    cfg.port = p;
                }
            }
            "--save" => {
                config::save(&cfg)?;
                println!("saved config to {}", config::config_path().display());
                return Ok(());
            }
            "--headless" => headless = true,
            other => {
                eprintln!("unknown argument: {other}\n");
                print_help();
                return Ok(());
            }
        }
        i += 1;
    }

    let threads = if cfg.threads == 0 { num_cpus::get() } else { cfg.threads };
    let my_fp = short_fp(&cfg.public_hex());
    let state = Arc::new(Mutex::new(AppState::new(my_fp, threads)));
    state.lock().unwrap().log("pcminer started - the phone is the master");

    // Background worker: discovery, pairing, and the mining loop.
    let worker_state = state.clone();
    let worker_cfg = cfg.clone();
    let worker = std::thread::spawn(move || client::run(worker_state, worker_cfg));

    if headless {
        run_headless(&state);
    } else {
        run_tui(&state)?;
    }

    // Signal the worker to stop and wind down.
    state.lock().unwrap().want_quit = true;
    let _ = worker.join();
    Ok(())
}

fn run_tui(state: &Arc<Mutex<AppState>>) -> Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let result = tui_loop(state, &mut terminal);

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn tui_loop<B: Backend>(state: &Arc<Mutex<AppState>>, terminal: &mut Terminal<B>) -> Result<()> {
    loop {
        {
            let s = state.lock().unwrap();
            terminal.draw(|f| ui::draw(f, &s))?;
        }

        if event::poll(Duration::from_millis(120))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                let mut s = state.lock().unwrap();
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        s.want_quit = true;
                        return Ok(());
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        s.want_quit = true;
                        return Ok(());
                    }
                    KeyCode::Char('p') => {
                        s.want_pause = !s.want_pause;
                    }
                    KeyCode::Char('r') => {
                        s.want_rescan = true;
                        s.log("manual LAN rescan requested");
                    }
                    _ => {}
                }
            }
        }

        if state.lock().unwrap().want_quit {
            return Ok(());
        }
    }
}

/// A minimal no-TUI mode for logs/CI or headless boxes: prints status lines.
fn run_headless(state: &Arc<Mutex<AppState>>) {
    use std::time::Instant;
    let mut last = Instant::now();
    let mut seen = 0usize;
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let s = state.lock().unwrap();
        // Flush any new log lines.
        if s.log.len() > seen {
            for line in s.log.iter().skip(seen) {
                println!("{line}");
            }
            seen = s.log.len();
        }
        if last.elapsed() >= Duration::from_secs(5) {
            last = Instant::now();
            println!(
                "[{}] {} | hashrate {} | shares ok {}/{}",
                s.phase.label(),
                s.status_detail,
                fmt_rate(s.hashrate),
                s.accepted,
                s.found
            );
        }
        if s.want_quit {
            return;
        }
    }
}

fn fmt_rate(h: f64) -> String {
    app::fmt_hashrate(h)
}

fn short_fp(pk_hex: &str) -> String {
    if pk_hex.len() >= 10 {
        format!("{}..{}", &pk_hex[..6], &pk_hex[pk_hex.len() - 4..])
    } else {
        pk_hex.to_string()
    }
}

fn print_help() {
    let path = config::config_path();
    println!(
        "MicroMiner PC Worker - lends hashing power to a paired phone.\n\
         \n\
         USAGE:\n\
         \x20   pcminer [OPTIONS]\n\
         \n\
         OPTIONS:\n\
         \x20   --host <ip:port>   Connect to a fixed phone address (skip discovery)\n\
         \x20   --name <name>      Worker name shown on the phone's pairing modal\n\
         \x20   --threads <n>      CPU mining threads (0 = all cores)\n\
         \x20   --port <port>      Share port (default 48510)\n\
         \x20   --print-id         Print this worker's public key and exit\n\
         \x20   --save             Persist the given options to the config and exit\n\
         \x20   --headless         Run without the TUI (status lines only)\n\
         \x20   -h, --help         Show this help\n\
         \n\
         The phone is always the master: it owns the pool and wallet and validates\n\
         every share. The first time you connect, confirm the pairing on the phone\n\
         (unless auto-trust is on). Mining only runs while the phone's miner is armed.\n\
         \n\
         Config: {}\n",
        path.display()
    );
}
