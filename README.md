<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# pcminer

A desktop worker that lends a PC's hashing power to a paired MicroMiner phone
over the LAN. The phone stays in charge: it owns the pool connection and the
wallet, builds every block header, checks every returned nonce and submits the
shares. `pcminer` only sweeps nonce ranges; it never talks to the pool or sees
the wallet.

## How it works

```
   ┌─────────┐  UDP DISCOVER ───────────►  ┌──────────────┐
   │   PC    │  ◄─────────── OFFER         │    phone     │
   │ pcminer │  TCP HELLO (x25519 pk) ───► │ share_server │
   │ (worker)│  ◄─── OK (device pk)  /DENY │  (master)    │
   │         │  ══ crypto_box channel ══   │              │
   │         │  ◄── JOB (+ gen/epoch/algo) │   owns pool  │
   │  sweep  │  ─── FOUND (nonce,sid) ───► │  + wallet    │
   └─────────┘  ◄── RESULT / WAIT / IDLE   └──────────────┘
```

* **Discovery.** The worker broadcasts `MMSHARE1 DISCOVER` and the phone
  answers with its identity and TCP port. Use `--host ip:port` to skip this.
* **Pairing.** Both sides have a long-term Curve25519 key. On first connect
  the phone asks you to confirm the worker (or pins it automatically if
  auto-trust is on). After that every frame is encrypted and authenticated
  with NaCl `crypto_box` (XSalsa20-Poly1305).
* **Work.** While its miner is armed and the pool has a job, the phone sends
  `JOB` frames (76-byte header prefix, target, nonce range, `gen`/`epoch`/
  `algo`). The worker returns winning nonces with a submit id and the phone
  re-checks and submits them. `WAIT` and `IDLE` drop in-flight work. See
  [`docs/net/PCMINER_SYNC.md`](../docs/net/PCMINER_SYNC.md).

The crypto in `src/nacl.rs` is a port of the TweetNaCl used on the device.
`cargo test` checks it against the RFC 7748 X25519 vectors, the NaCl secretbox
vector and the Bitcoin genesis block.

## Building

```sh
cargo build --release
./target/release/pcminer            # interactive TUI; auto-discovers the phone
```

The first run creates a persistent identity; `pcminer --print-id` shows its
public key and where it is stored. Confirm the pairing on the phone the first
time you connect.

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

`q` quit, `p` pause/resume, `r` rescan the LAN.

## GPU backend (OpenCL)

An OpenCL sha256d backend is available behind the `gpu` feature (`src/gpu.rs`,
`src/sha256d.cl`). It falls back to the CPU backend if no device can be
initialised.

```sh
cargo build --release --features gpu
```

Linking needs an OpenCL import library: `OpenCL.lib` for MSVC or `libOpenCL.a`
for MinGW. They ship with the NVIDIA, AMD and Intel SDKs; a MinGW one is
included under `third_party/opencl/`. The GPU path hasn't been tested much on
real hardware, so check that shares are accepted on a test pool first.

## Security

* The phone pins the worker's public key. A new key needs a new pairing.
* A worker can't submit to the pool, read the wallet or arm the miner.
* Work is only handed out while the phone's miner is armed.
