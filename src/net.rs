// SPDX-License-Identifier: GPL-3.0-or-later
//
// MicroMiner OS - PC share miner: framed socket + encrypted session.
// Copyright (C) 2026 Vakea
//
// Wire format mirrors src/net/share_server.c exactly:
//   * every frame is a 4-byte big-endian length prefix followed by that many
//     payload bytes;
//   * the handshake frames (HELLO / OK / DENY) are plaintext;
//   * after the handshake every frame payload is `tag(16) || ciphertext`, sealed
//     with NaCl crypto_box_afternm under the precomputed shared key and a
//     per-direction, per-counter 24-byte nonce.

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::nacl;

pub const PROTO: &str = "MMSHARE1";
pub const MAX_FRAME: usize = 4096;

// ---- raw framed I/O ----------------------------------------------------

pub fn send_frame(sock: &mut TcpStream, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        bail!("frame too large ({} bytes)", payload.len());
    }
    let n = payload.len() as u32;
    let hdr = [(n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    sock.write_all(&hdr)?;
    sock.write_all(payload)?;
    Ok(())
}

pub fn recv_frame(sock: &mut TcpStream) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    sock.read_exact(&mut hdr)?;
    let len = ((hdr[0] as usize) << 24)
        | ((hdr[1] as usize) << 16)
        | ((hdr[2] as usize) << 8)
        | (hdr[3] as usize);
    if len > MAX_FRAME {
        bail!("frame length {len} exceeds cap");
    }
    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf)?;
    Ok(buf)
}

// ---- encrypted session -------------------------------------------------

pub struct Session {
    sock: TcpStream,
    k: [u8; 32],
    base_tx: [u8; 24], // PC -> phone (P2S)
    base_rx: [u8; 24], // phone -> PC (S2P)
    ctr_tx: u64,
    ctr_rx: u64,
    pub device_name: String,
    pub device_pk: [u8; 32],
}

/// Distinguishes a read that timed out (so the caller can keep working) from a
/// real connection error.
pub enum RecvOutcome {
    Msg(String),
    Timeout,
}

fn make_nonce(base: &[u8; 24], ctr: u64) -> [u8; 24] {
    let mut n = *base;
    for i in 0..8 {
        n[24 - 1 - i] = (ctr >> (8 * i)) as u8;
    }
    n
}

fn derive_base(tag: &[u8; 4], nc: &[u8; 24], ns: &[u8; 24]) -> [u8; 24] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(nc);
    h.update(ns);
    let digest = h.finalize();
    let mut base = [0u8; 24];
    base.copy_from_slice(&digest[..24]);
    base
}

impl Session {
    /// Perform the client handshake and return an established session.
    ///
    /// `connect_wait` bounds how long we block for the phone's reply, which may
    /// include the user confirming the pairing modal on the device.
    pub fn handshake(
        mut sock: TcpStream,
        my_pk: &[u8; 32],
        my_sk: &[u8; 32],
        worker_name: &str,
        connect_wait: Duration,
    ) -> Result<Session> {
        sock.set_nodelay(true).ok();

        // Client nonce.
        let mut nonce_c = [0u8; 24];
        nacl::randombytes(&mut nonce_c);

        // Names must be single-token on the phone's scanf; keep it tidy.
        let safe_name: String = worker_name
            .chars()
            .map(|c| if c.is_whitespace() { '_' } else { c })
            .take(48)
            .collect();

        let hello = format!(
            "{PROTO} HELLO {} {} {}",
            hex::encode(my_pk),
            hex::encode(nonce_c),
            safe_name
        );
        send_frame(&mut sock, hello.as_bytes())?;

        // Wait (bounded) for OK/DENY - the device may be prompting the user.
        sock.set_read_timeout(Some(connect_wait)).ok();
        let reply = recv_frame(&mut sock).map_err(|e| anyhow!("no handshake reply: {e}"))?;
        let reply = String::from_utf8_lossy(&reply).to_string();
        let parts: Vec<&str> = reply.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == PROTO && parts[1] == "DENY" {
            bail!("the phone denied this worker");
        }
        if parts.len() < 5 || parts[0] != PROTO || parts[1] != "OK" {
            bail!("unexpected handshake reply: {reply}");
        }
        let device_pk_v = hex::decode(parts[2]).map_err(|_| anyhow!("bad device pubkey"))?;
        let nonce_s_v = hex::decode(parts[3]).map_err(|_| anyhow!("bad server nonce"))?;
        if device_pk_v.len() != 32 || nonce_s_v.len() != 24 {
            bail!("handshake field sizes wrong");
        }
        let mut device_pk = [0u8; 32];
        device_pk.copy_from_slice(&device_pk_v);
        let mut nonce_s = [0u8; 24];
        nonce_s.copy_from_slice(&nonce_s_v);
        let device_name = parts[4..].join(" ");

        // Session key + per-direction nonce bases (match derive_bases()).
        let k = nacl::box_beforenm(&device_pk, my_sk);
        let base_rx = derive_base(b"S2P\0", &nonce_c, &nonce_s); // phone -> PC
        let base_tx = derive_base(b"P2S\0", &nonce_c, &nonce_s); // PC -> phone

        Ok(Session {
            sock,
            k,
            base_tx,
            base_rx,
            ctr_tx: 0,
            ctr_rx: 0,
            device_name,
            device_pk,
        })
    }

    /// Set the per-recv blocking timeout for the work loop.
    pub fn set_read_timeout(&mut self, d: Option<Duration>) {
        self.sock.set_read_timeout(d).ok();
    }

    pub fn send(&mut self, text: &str) -> Result<()> {
        let nonce = make_nonce(&self.base_tx, self.ctr_tx);
        self.ctr_tx += 1;
        let wire = nacl::box_afternm_seal(&self.k, &nonce, text.as_bytes());
        send_frame(&mut self.sock, &wire)
    }

    /// Receive one decrypted message. A socket read timeout returns `Timeout`
    /// rather than an error so the caller can push work and heartbeats.
    pub fn recv(&mut self) -> Result<RecvOutcome> {
        let wire = match recv_frame(&mut self.sock) {
            Ok(w) => w,
            Err(e) => {
                if let Some(io) = e.downcast_ref::<std::io::Error>() {
                    if matches!(
                        io.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) {
                        return Ok(RecvOutcome::Timeout);
                    }
                }
                return Err(e);
            }
        };
        let nonce = make_nonce(&self.base_rx, self.ctr_rx);
        self.ctr_rx += 1;
        let pt = nacl::box_afternm_open(&self.k, &nonce, &wire)
            .ok_or_else(|| anyhow!("session authentication failed"))?;
        Ok(RecvOutcome::Msg(String::from_utf8_lossy(&pt).to_string()))
    }
}
