<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MicroMiner PC Worker (`pcminer`)

Lends this PC's hashing power to a paired phone over the LAN. **The phone is
always the master**: it owns the pool connection and the wallet, builds every
block header, validates every returned nonce, and submits every share under its
own credentials. This tool is a pure nonce-sweeper — it never talks to the pool
and never sees the wallet.

## How it works

```
   ┌─────────┐  UDP DISCOVER ───────────►  ┌──────────────┐
   │   PC    │  ◄─────────── OFFER         │    phone     │
   │ pcminer │  TCP HELLO (x25519 pk) ───► │ share_server │
   │ (worker)│  ◄─── OK (device pk)  /DENY │  (master)    │
   │         │  ══ crypto_box channel ══   │              │
   │         │  ◄── JOB (header+target)    │   owns pool  │
   │  sweep  │  ─── FOUND (nonce) ───────► │  + wallet    │
   └─────────┘  ◄── RESULT ok/bad/stale    └──────────────┘
```

* **Discovery** — broadcasts `MMSHARE1 DISCOVER`; the phone answers with its
  identity and TCP port, so you never type an IP (or pass `--host ip:port`).
* **Pairing** — both sides have a long-term Curve25519 "box" identity. On first
  connect the phone either shows a confirm/deny modal or (with auto-trust on)
  pins this PC's key automatically. After that every frame is encrypted and
  authenticated with NaCl `crypto_box` (XSalsa20-Poly1305).
* **Work** — the phone sends a `JOB` (76-byte header prefix, 8-word target, a
  nonce range) only while its miner is **armed** and the pool is connected. The
  PC sweeps the range (double-SHA-256), returns any winning nonce, and the phone
  re-validates and submits it. Nothing mines until the phone says so.

The crypto is a faithful in-tree port of the device's TweetNaCl
(`src/nacl.rs`), verified byte-for-byte against standard known-answer vectors
(X25519 RFC 7748, the canonical NaCl secretbox vector, Bitcoin-genesis
sha256d) — see `cargo test`.

## Build & run

```sh
cargo build --release
./target/release/pcminer            # interactive TUI; auto-discovers the phone
```

First run generates a persistent identity at the path printed by
`pcminer --print-id`. Confirm the pairing on the phone the first time (unless
auto-trust is enabled on the device).

### Options

| flag | meaning |
|------|---------|
| `--host <ip:port>` | connect to a fixed phone address (skip discovery) |
| `--name <name>`    | worker name shown on the phone's pairing modal |
| `--threads <n>`    | CPU mining threads (`0` = all cores) |
| `--port <port>`    | share port (default `48510`) |
| `--print-id`       | print this worker's public key + config path |
| `--save`           | persist the given options to the config file |
| `--headless`       | run without the TUI (status lines only) |

### TUI keys

`q` quit · `p` pause/resume · `r` rescan the LAN

## GPU (OpenCL) backend — optional, needs on-hardware validation

A full OpenCL sha256d backend lives behind the `gpu` cargo feature
(`src/gpu.rs` + `src/sha256d.cl`). Its kernel mirrors the CPU algorithm exactly
and it falls back to the CPU backend automatically if a device can't be
initialised.

```sh
cargo build --release --features gpu
```

Building with `--features gpu` requires an **OpenCL import library** for your
linker (`OpenCL.lib` for MSVC, or `libOpenCL.a` for the GNU/mingw toolchain) —
these ship with GPU vendor SDKs (NVIDIA CUDA, AMD, Intel) or the Khronos ICD
loader. The Rust side compiles cleanly; only the final link needs that library.
The GPU path has **not** been validated on real hardware yet — verify shares are
accepted on a test pool before relying on it.

## Security notes

* The PC holds its own long-term secret key; the phone pins the matching public
  key. A different key means a fresh pairing decision on the phone.
* The PC cannot submit shares to the pool directly, cannot read the wallet, and
  cannot arm the miner — all of that stays on the phone.
* Work is only distributed while the phone's miner is armed; the device never
  starts mining on its own.
