// SPDX-License-Identifier: GPL-3.0-or-later
//
// MicroMiner OS - PC share miner: LAN discovery of the phone.
// Copyright (C) 2026 Vakea
//
// Broadcasts "MMSHARE1 DISCOVER" on the share port and collects the phone's
// "MMSHARE1 OFFER <pk_hex> <tcp_port> <name>" replies, so the user never has to
// type an IP address.

use anyhow::Result;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::net::PROTO;

#[derive(Debug, Clone)]
pub struct Offer {
    pub addr: SocketAddr,
    pub pk_hex: String,
    pub name: String,
}

/// Broadcast a discovery probe and gather offers for `wait`.
pub fn discover(port: u16, wait: Duration) -> Result<Vec<Offer>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    sock.set_read_timeout(Some(Duration::from_millis(250)))?;

    let probe = format!("{PROTO} DISCOVER");
    // Global broadcast plus a couple of retries in case a packet is dropped.
    for _ in 0..3 {
        let _ = sock.send_to(probe.as_bytes(), (std::net::Ipv4Addr::BROADCAST, port));
        std::thread::sleep(Duration::from_millis(60));
    }

    let mut offers: Vec<Offer> = Vec::new();
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 512];
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if let Some(o) = parse_offer(&buf[..n], from) {
                    if !offers.iter().any(|e| e.pk_hex == o.pk_hex) {
                        offers.push(o);
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    Ok(offers)
}

fn parse_offer(data: &[u8], from: SocketAddr) -> Option<Offer> {
    let text = std::str::from_utf8(data).ok()?;
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 4 || parts[0] != PROTO || parts[1] != "OFFER" {
        return None;
    }
    let pk_hex = parts[2].to_string();
    let tcp_port: u16 = parts[3].parse().ok()?;
    let name = if parts.len() > 4 { parts[4..].join(" ") } else { "phone".to_string() };
    let mut addr = from;
    addr.set_port(tcp_port);
    Some(Offer { addr, pk_hex, name })
}
