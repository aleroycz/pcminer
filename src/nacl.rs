// SPDX-License-Identifier: GPL-3.0-or-later
//
// TweetNaCl crypto_box subset for MMSHARE1; wire layout matches src/ota/tweetnacl.c.
//
// Copyright (C) 2026 Vakea

#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)] /* TweetNaCl port: keep loop form faithful to C */

type Gf = [i64; 16];

const ZERO16: [u8; 16] = [0u8; 16];
const NINE: [u8; 32] = {
    let mut a = [0u8; 32];
    a[0] = 9;
    a
};
const SIGMA: [u8; 16] = *b"expand 32-byte k";
const C121665: Gf = {
    let mut a = [0i64; 16];
    a[0] = 0xDB41;
    a[1] = 1;
    a
};

// Protocol sizes (documentation; mirror tweetnacl's crypto_box_* defines).
#[allow(dead_code)]
pub const PUBLICKEYBYTES: usize = 32;
#[allow(dead_code)]
pub const SECRETKEYBYTES: usize = 32;
#[allow(dead_code)]
pub const BEFORENMBYTES: usize = 32;
#[allow(dead_code)]
pub const NONCEBYTES: usize = 24;
pub const ZEROBYTES: usize = 32;
pub const BOXZEROBYTES: usize = 16;
pub const MACBYTES: usize = ZEROBYTES - BOXZEROBYTES; // 16

// ---- little-endian 32-bit load/store -----------------------------------

#[inline]
fn ld32(x: &[u8]) -> u32 {
    (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16) | ((x[3] as u32) << 24)
}

#[inline]
fn st32(x: &mut [u8], mut u: u32) {
    for i in 0..4 {
        x[i] = (u & 0xff) as u8;
        u >>= 8;
    }
}

#[inline]
fn l32(x: u32, c: u32) -> u32 {
    x.rotate_left(c)
}

// ---- constant-time compare ---------------------------------------------

fn vn(x: &[u8], y: &[u8], n: usize) -> i32 {
    let mut d: u32 = 0;
    for i in 0..n {
        d |= (x[i] ^ y[i]) as u32;
    }
    (1u32 & (d.wrapping_sub(1) >> 8)) as i32 - 1
}

fn crypto_verify_16(x: &[u8], y: &[u8]) -> i32 {
    vn(x, y, 16)
}

// ---- Salsa20 / HSalsa20 core -------------------------------------------

fn core(out: &mut [u8], inp: &[u8], k: &[u8], c: &[u8], h: bool) {
    let mut w = [0u32; 16];
    let mut x = [0u32; 16];
    let mut y = [0u32; 16];
    let mut t = [0u32; 4];

    for i in 0..4 {
        x[5 * i] = ld32(&c[4 * i..]);
        x[1 + i] = ld32(&k[4 * i..]);
        x[6 + i] = ld32(&inp[4 * i..]);
        x[11 + i] = ld32(&k[16 + 4 * i..]);
    }
    for i in 0..16 {
        y[i] = x[i];
    }
    for _ in 0..20 {
        for j in 0..4 {
            for m in 0..4 {
                t[m] = x[(5 * j + 4 * m) % 16];
            }
            t[1] ^= l32(t[0].wrapping_add(t[3]), 7);
            t[2] ^= l32(t[1].wrapping_add(t[0]), 9);
            t[3] ^= l32(t[2].wrapping_add(t[1]), 13);
            t[0] ^= l32(t[3].wrapping_add(t[2]), 18);
            for m in 0..4 {
                w[4 * j + (j + m) % 4] = t[m];
            }
        }
        for m in 0..16 {
            x[m] = w[m];
        }
    }

    if h {
        for i in 0..16 {
            x[i] = x[i].wrapping_add(y[i]);
        }
        for i in 0..4 {
            x[5 * i] = x[5 * i].wrapping_sub(ld32(&c[4 * i..]));
            x[6 + i] = x[6 + i].wrapping_sub(ld32(&inp[4 * i..]));
        }
        for i in 0..4 {
            st32(&mut out[4 * i..], x[5 * i]);
            st32(&mut out[16 + 4 * i..], x[6 + i]);
        }
    } else {
        for i in 0..16 {
            st32(&mut out[4 * i..], x[i].wrapping_add(y[i]));
        }
    }
}

fn crypto_core_salsa20(out: &mut [u8; 64], inp: &[u8; 16], k: &[u8; 32]) {
    core(out, inp, k, &SIGMA, false);
}

fn crypto_core_hsalsa20(out: &mut [u8; 32], inp: &[u8; 16], k: &[u8; 32]) {
    core(out, inp, k, &SIGMA, true);
}

// ---- Salsa20 / XSalsa20 stream (xor) -----------------------------------

fn crypto_stream_salsa20_xor(c: &mut [u8], m: Option<&[u8]>, mut b: u64, n: &[u8], k: &[u8; 32]) {
    if b == 0 {
        return;
    }
    let mut z = [0u8; 16];
    let mut x = [0u8; 64];
    z[..8].copy_from_slice(&n[..8]);
    let mut coff = 0usize;
    let mut moff = 0usize;
    while b >= 64 {
        crypto_core_salsa20(&mut x, &z, k);
        for i in 0..64 {
            let mi = m.map(|m| m[moff + i]).unwrap_or(0);
            c[coff + i] = mi ^ x[i];
        }
        let mut u: u32 = 1;
        for i in 8..16 {
            u += z[i] as u32;
            z[i] = (u & 0xff) as u8;
            u >>= 8;
        }
        b -= 64;
        coff += 64;
        if m.is_some() {
            moff += 64;
        }
    }
    if b > 0 {
        crypto_core_salsa20(&mut x, &z, k);
        for i in 0..(b as usize) {
            let mi = m.map(|m| m[moff + i]).unwrap_or(0);
            c[coff + i] = mi ^ x[i];
        }
    }
}

fn crypto_stream_xsalsa20_xor(c: &mut [u8], m: Option<&[u8]>, d: u64, n: &[u8], k: &[u8; 32]) {
    let mut s = [0u8; 32];
    let mut n16 = [0u8; 16];
    n16.copy_from_slice(&n[..16]);
    crypto_core_hsalsa20(&mut s, &n16, k);
    crypto_stream_salsa20_xor(c, m, d, &n[16..], &s);
}

fn crypto_stream_xsalsa20(c: &mut [u8], d: u64, n: &[u8], k: &[u8; 32]) {
    let mut s = [0u8; 32];
    let mut n16 = [0u8; 16];
    n16.copy_from_slice(&n[..16]);
    crypto_core_hsalsa20(&mut s, &n16, k);
    crypto_stream_salsa20_xor(c, None, d, &n[16..], &s);
}

// ---- Poly1305 ----------------------------------------------------------

const MINUSP: [u32; 17] = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252];

fn add1305(h: &mut [u32; 17], c: &[u32; 17]) {
    let mut u: u32 = 0;
    for j in 0..17 {
        u = u.wrapping_add(h[j].wrapping_add(c[j]));
        h[j] = u & 255;
        u >>= 8;
    }
}

fn crypto_onetimeauth(out: &mut [u8], m: &[u8], mut n: u64, k: &[u8]) {
    let mut r = [0u32; 17];
    let mut h = [0u32; 17];
    let mut c = [0u32; 17];
    let mut g = [0u32; 17];
    let mut x = [0u32; 17];

    for j in 0..16 {
        r[j] = k[j] as u32;
    }
    r[3] &= 15;
    r[4] &= 252;
    r[7] &= 15;
    r[8] &= 252;
    r[11] &= 15;
    r[12] &= 252;
    r[15] &= 15;

    let mut moff = 0usize;
    while n > 0 {
        for j in 0..17 {
            c[j] = 0;
        }
        let mut j = 0usize;
        while j < 16 && (j as u64) < n {
            c[j] = m[moff + j] as u32;
            j += 1;
        }
        c[j] = 1;
        moff += j;
        n -= j as u64;
        add1305(&mut h, &c);
        for i in 0..17 {
            x[i] = 0;
            for jj in 0..17 {
                let rr = if jj <= i {
                    r[i - jj]
                } else {
                    320u32.wrapping_mul(r[i + 17 - jj])
                };
                x[i] = x[i].wrapping_add(h[jj].wrapping_mul(rr));
            }
        }
        for i in 0..17 {
            h[i] = x[i];
        }
        let mut u: u32 = 0;
        for j in 0..16 {
            u = u.wrapping_add(h[j]);
            h[j] = u & 255;
            u >>= 8;
        }
        u = u.wrapping_add(h[16]);
        h[16] = u & 3;
        u = 5u32.wrapping_mul(u >> 2);
        for j in 0..16 {
            u = u.wrapping_add(h[j]);
            h[j] = u & 255;
            u >>= 8;
        }
        u = u.wrapping_add(h[16]);
        h[16] = u;
    }

    for j in 0..17 {
        g[j] = h[j];
    }
    add1305(&mut h, &MINUSP);
    let s: u32 = 0u32.wrapping_sub(h[16] >> 7);
    for j in 0..17 {
        h[j] ^= s & (g[j] ^ h[j]);
    }

    for j in 0..16 {
        c[j] = k[j + 16] as u32;
    }
    c[16] = 0;
    add1305(&mut h, &c);
    for j in 0..16 {
        out[j] = (h[j] & 0xff) as u8;
    }
}

fn crypto_onetimeauth_verify(h: &[u8], m: &[u8], n: u64, k: &[u8]) -> i32 {
    let mut x = [0u8; 16];
    crypto_onetimeauth(&mut x, m, n, k);
    crypto_verify_16(h, &x)
}

// ---- secretbox (XSalsa20-Poly1305) -------------------------------------

/// secretbox seal: ZEROBYTES plaintext in; BOXZEROBYTES + tag + ciphertext out.
fn crypto_secretbox(c: &mut [u8], m: &[u8], d: u64, n: &[u8], k: &[u8; 32]) -> i32 {
    if d < 32 {
        return -1;
    }
    crypto_stream_xsalsa20_xor(c, Some(m), d, n, k);
    // auth over c[32..d] with key c[0..32]
    let (auth_key, rest) = c.split_at_mut(32);
    let mut tag = [0u8; 16];
    crypto_onetimeauth(&mut tag, &rest[0..(d as usize - 32)], d - 32, auth_key);
    c[16..32].copy_from_slice(&tag);
    for i in 0..16 {
        c[i] = 0;
    }
    0
}

/// secretbox open: authenticated decrypt back to ZEROBYTES-padded plaintext.
fn crypto_secretbox_open(m: &mut [u8], c: &[u8], d: u64, n: &[u8], k: &[u8; 32]) -> i32 {
    if d < 32 {
        return -1;
    }
    let mut x = [0u8; 32];
    crypto_stream_xsalsa20(&mut x, 32, n, k);
    if crypto_onetimeauth_verify(&c[16..32], &c[32..(d as usize)], d - 32, &x) != 0 {
        return -1;
    }
    crypto_stream_xsalsa20_xor(m, Some(c), d, n, k);
    for i in 0..32 {
        m[i] = 0;
    }
    0
}

// ---- field arithmetic (GF(2^255-19)) -----------------------------------

fn set25519(r: &mut Gf, a: &Gf) {
    r.copy_from_slice(a);
}

fn car25519(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1i64 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            // o[0] += (c-1) + 37*(c-1) == 38*(c-1)  (the 2^256 == 38 reduction)
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
    }
}

fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn pack25519(o: &mut [u8], n: &Gf) {
    let mut t: Gf = [0; 16];
    let mut m: Gf = [0; 16];
    set25519(&mut t, n);
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(&mut t, &mut m, 1 - b);
    }
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
    }
}

fn unpack25519(o: &mut Gf, n: &[u8]) {
    for i in 0..16 {
        o[i] = n[2 * i] as i64 + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
}

fn fadd(o: &mut Gf, a: &Gf, b: &Gf) {
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
}

fn fsub(o: &mut Gf, a: &Gf, b: &Gf) {
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
}

fn fmul(o: &mut Gf, a: &Gf, b: &Gf) {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut r: Gf = [0; 16];
    r.copy_from_slice(&t[0..16]);
    car25519(&mut r);
    car25519(&mut r);
    o.copy_from_slice(&r);
}

fn fsqr(o: &mut Gf, a: &Gf) {
    let aa = *a;
    fmul(o, &aa, &aa);
}

fn inv25519(o: &mut Gf, i: &Gf) {
    let mut c: Gf = *i;
    for a in (0..=253).rev() {
        let cc = c;
        fsqr(&mut c, &cc);
        if a != 2 && a != 4 {
            let cc2 = c;
            fmul(&mut c, &cc2, i);
        }
    }
    o.copy_from_slice(&c);
}

fn crypto_scalarmult(q: &mut [u8], n: &[u8], p: &[u8]) {
    let mut z = [0u8; 32];
    z[..31].copy_from_slice(&n[..31]);
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;

    let mut x0: Gf = [0; 16];
    unpack25519(&mut x0, p);

    let mut a: Gf = [0; 16];
    let mut b: Gf = x0;
    let mut c: Gf = [0; 16];
    let mut d: Gf = [0; 16];
    let mut e: Gf = [0; 16];
    let mut f: Gf = [0; 16];
    a[0] = 1;
    d[0] = 1;

    for i in (0..=254).rev() {
        let r = ((z[i >> 3] >> (i & 7)) & 1) as i64;
        sel25519(&mut a, &mut b, r);
        sel25519(&mut c, &mut d, r);
        fadd(&mut e, &a, &c);
        let at = a;
        fsub(&mut a, &at, &c);
        fadd(&mut c, &b, &d);
        let bt = b;
        fsub(&mut b, &bt, &d);
        fsqr(&mut d, &e);
        fsqr(&mut f, &a);
        let ct = c;
        let a_old = a;
        fmul(&mut a, &ct, &a_old);
        fmul(&mut c, &b, &e);
        fadd(&mut e, &a, &c);
        let at2 = a;
        fsub(&mut a, &at2, &c);
        fsqr(&mut b, &a);
        fsub(&mut c, &d, &f);
        let ct2 = c;
        fmul(&mut a, &ct2, &C121665);
        let at3 = a;
        fadd(&mut a, &at3, &d);
        let ct3 = c;
        let a_now = a;
        fmul(&mut c, &ct3, &a_now);
        fmul(&mut a, &d, &f);
        fmul(&mut d, &b, &x0);
        let bt2 = b;
        fsqr(&mut b, &e);
        let _ = bt2;
        sel25519(&mut a, &mut b, r);
        sel25519(&mut c, &mut d, r);
    }

    let mut cinv: Gf = [0; 16];
    inv25519(&mut cinv, &c);
    let mut res: Gf = [0; 16];
    fmul(&mut res, &a, &cinv);
    pack25519(q, &res);
}

fn crypto_scalarmult_base(q: &mut [u8], n: &[u8]) {
    crypto_scalarmult(q, n, &NINE);
}

// ---- public crypto_box API ---------------------------------------------

/// Generate a long-term box keypair. Returns (public, secret).
pub fn box_keypair() -> ([u8; 32], [u8; 32]) {
    let mut sk = [0u8; 32];
    randombytes(&mut sk);
    let mut pk = [0u8; 32];
    crypto_scalarmult_base(&mut pk, &sk);
    (pk, sk)
}

/// Derive the public key for a given secret key.
pub fn box_public_from_secret(sk: &[u8; 32]) -> [u8; 32] {
    let mut pk = [0u8; 32];
    crypto_scalarmult_base(&mut pk, sk);
    pk
}

/// Precompute the shared box key (NaCl crypto_box_beforenm).
pub fn box_beforenm(their_pk: &[u8; 32], my_sk: &[u8; 32]) -> [u8; 32] {
    let mut s = [0u8; 32];
    crypto_scalarmult(&mut s, my_sk, their_pk);
    let mut k = [0u8; 32];
    crypto_core_hsalsa20(&mut k, &ZERO16, &s);
    k
}

/// afternm seal: wire format is 16-byte Poly1305 tag then ciphertext.
pub fn box_afternm_seal(k: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Vec<u8> {
    let d = ZEROBYTES + plaintext.len();
    let mut m = vec![0u8; d];
    m[ZEROBYTES..].copy_from_slice(plaintext);
    let mut c = vec![0u8; d];
    crypto_secretbox(&mut c, &m, d as u64, nonce, k);
    // on-wire = c[BOXZEROBYTES..] = [tag(16)][ciphertext]
    c[BOXZEROBYTES..].to_vec()
}

/// afternm open: None on Poly1305 failure.
pub fn box_afternm_open(k: &[u8; 32], nonce: &[u8; 24], wire: &[u8]) -> Option<Vec<u8>> {
    if wire.len() < MACBYTES {
        return None;
    }
    let d = BOXZEROBYTES + wire.len();
    let mut c = vec![0u8; d];
    c[BOXZEROBYTES..].copy_from_slice(wire);
    let mut m = vec![0u8; d];
    if crypto_secretbox_open(&mut m, &c, d as u64, nonce, k) != 0 {
        return None;
    }
    Some(m[ZEROBYTES..].to_vec())
}

/// Fill `buf` with cryptographically secure random bytes.
pub fn randombytes(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    // X25519 RFC 7748 test vector.
    #[test]
    fn x25519_rfc7748() {
        let scalar = hex_to("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let point = hex_to("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expect = hex_to("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        let mut out = [0u8; 32];
        crypto_scalarmult(&mut out, &scalar, &point);
        assert_eq!(&out[..], &expect[..]);
    }

    // A full seal/open round-trip under a precomputed key.
    #[test]
    fn box_roundtrip() {
        let (apk, ask) = box_keypair();
        let (bpk, bsk) = box_keypair();
        let ka = box_beforenm(&bpk, &ask);
        let kb = box_beforenm(&apk, &bsk);
        assert_eq!(ka, kb);
        let nonce = [7u8; 24];
        let msg = b"JOB 1 deadbeef";
        let wire = box_afternm_seal(&ka, &nonce, msg);
        assert_eq!(wire.len(), msg.len() + MACBYTES);
        let open = box_afternm_open(&kb, &nonce, &wire).expect("auth");
        assert_eq!(&open[..], &msg[..]);
        // A flipped bit must fail authentication.
        let mut bad = wire.clone();
        bad[0] ^= 1;
        assert!(box_afternm_open(&kb, &nonce, &bad).is_none());
    }

    // NaCl secretbox KAT ("Bob" message) pins tag-first layout vs tweetnacl.c.
    #[test]
    fn secretbox_nacl_kat() {
        let firstkey: [u8; 32] = [
            0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a,
            0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08,
            0x44, 0xf6, 0x83, 0x89,
        ];
        let nonce: [u8; 24] = [
            0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc,
            0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37,
        ];
        let msg: [u8; 131] = [
            0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb,
            0x0c, 0x7b, 0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4, 0x4b, 0x66, 0x84, 0x9b,
            0x64, 0x24, 0x4f, 0xfc, 0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a, 0x1a, 0xc7,
            0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29, 0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4,
            0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31, 0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46,
            0xf0, 0x6d, 0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57, 0xe2, 0xf6, 0x55, 0x6a,
            0xd6, 0xb1, 0x31, 0x8a, 0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde, 0x04, 0x89,
            0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
            0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40, 0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38,
            0x48, 0x64, 0x5e, 0x07, 0x05,
        ];
        let expect: [u8; 147] = [
            0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5, 0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33,
            0x05, 0xd9, 0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73, 0xc2, 0x96, 0x50, 0xba,
            0x32, 0xfc, 0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4, 0x47, 0x6f,
            0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a, 0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
            0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72, 0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92,
            0x8f, 0xe2, 0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3,
            0x14, 0xa7, 0xcc, 0x8a, 0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae, 0x90, 0x22,
            0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea, 0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
            0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde, 0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5,
            0xf9, 0xb3, 0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6, 0x59, 0x9b, 0x1f, 0x65,
            0x4c, 0xb4, 0x5a, 0x74, 0xe3, 0x55, 0xa5,
        ];
        let wire = box_afternm_seal(&firstkey, &nonce, &msg);
        assert_eq!(wire.len(), expect.len());
        assert_eq!(&wire[..], &expect[..]);
        // And it opens back.
        let open = box_afternm_open(&firstkey, &nonce, &wire).expect("auth");
        assert_eq!(&open[..], &msg[..]);
    }

    fn hex_to(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        let b = s.as_bytes();
        for i in 0..32 {
            let hi = (b[2 * i] as char).to_digit(16).unwrap();
            let lo = (b[2 * i + 1] as char).to_digit(16).unwrap();
            o[i] = ((hi << 4) | lo) as u8;
        }
        o
    }
}
