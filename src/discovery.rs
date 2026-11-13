// SPDX-License-Identifier: GPL-3.0-or-later
//
// UDP MMSHARE1 DISCOVER/OFFER to locate the phone without a fixed IP.
//
// Copyright (C) 2026 Vakea

use anyhow::Result;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::net::PROTO;

#[derive(Debug, Clone)]
pub struct Offer {
    pub addr: SocketAddr,
    pub pk_hex: String,
    pub name: String,
}

/// Broadcast a discovery probe and gather offers for `wait`.
///
/// Windows Wi-Fi often drops global `255.255.255.255` broadcasts, so we also
/// probe each local IPv4 subnet's directed broadcast and (optionally) a known
/// unicast hint.
pub fn discover(port: u16, wait: Duration) -> Result<Vec<Offer>> {
    discover_ex(port, wait, &[])
}

/// Like [`discover`], but also unicasts DISCOVER to `hints` (e.g. a saved host).
pub fn discover_ex(port: u16, wait: Duration, hints: &[SocketAddr]) -> Result<Vec<Offer>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    sock.set_read_timeout(Some(Duration::from_millis(250)))?;

    let probe = format!("{PROTO} DISCOVER");
    let targets = broadcast_targets(port, hints);

    for _ in 0..4 {
        for dest in &targets {
            let _ = sock.send_to(probe.as_bytes(), dest);
        }
        std::thread::sleep(Duration::from_millis(80));
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

fn broadcast_targets(port: u16, hints: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    out.push(SocketAddr::from((Ipv4Addr::BROADCAST, port)));
    for h in hints {
        if !out.contains(h) {
            out.push(*h);
        }
    }
    for (ip, prefix) in local_ipv4s() {
        if let Some(bcast) = directed_broadcast(ip, prefix) {
            let a = SocketAddr::from((bcast, port));
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    out
}

fn directed_broadcast(ip: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if prefix > 32 || ip.is_loopback() || ip.is_link_local() {
        return None;
    }
    let ip_u = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some(Ipv4Addr::from(ip_u | !mask))
}

/// Best-effort local IPv4 list (Windows: `Get-NetIPAddress`-style via ipconfig).
fn local_ipv4s() -> Vec<(Ipv4Addr, u8)> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        if let Ok(txt) = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { \"$($_.IPAddress)/$($_.PrefixLength)\" }",
            ])
            .output()
        {
            if txt.status.success() {
                for line in String::from_utf8_lossy(&txt.stdout).lines() {
                    if let Some((a, b)) = line.trim().split_once('/') {
                        if let (Ok(ip), Ok(pref)) = (a.parse::<Ipv4Addr>(), b.parse::<u8>()) {
                            if !ip.is_loopback() {
                                out.push((ip, pref));
                            }
                        }
                    }
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        // Fallback: parse `ip -4 -o addr` when available.
        if let Ok(txt) = std::process::Command::new("ip")
            .args(["-4", "-o", "addr", "show"])
            .output()
        {
            if txt.status.success() {
                for line in String::from_utf8_lossy(&txt.stdout).lines() {
                    // ... inet 192.168.1.2/24 ...
                    if let Some(idx) = line.find("inet ") {
                        let rest = &line[idx + 5..];
                        let token = rest.split_whitespace().next().unwrap_or("");
                        if let Some((a, b)) = token.split_once('/') {
                            if let (Ok(ip), Ok(pref)) = (a.parse::<Ipv4Addr>(), b.parse::<u8>()) {
                                if !ip.is_loopback() {
                                    out.push((ip, pref));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

fn parse_offer(data: &[u8], from: SocketAddr) -> Option<Offer> {
    let text = std::str::from_utf8(data).ok()?;
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 4 || parts[0] != PROTO || parts[1] != "OFFER" {
        return None;
    }
    let pk_hex = parts[2].to_string();
    let tcp_port: u16 = parts[3].parse().ok()?;
    let name = if parts.len() > 4 {
        parts[4..].join(" ")
    } else {
        "phone".to_string()
    };
    let mut addr = from;
    addr.set_port(tcp_port);
    Some(Offer { addr, pk_hex, name })
}
