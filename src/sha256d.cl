// SPDX-License-Identifier: GPL-3.0-or-later
//
// MicroMiner OS - PC share miner: OpenCL sha256d search kernel (midstate).
// Copyright (C) 2026 Vakea
//
// Host precomputes SHA-256 midstate over header bytes 0..63. Each work item
// only runs the second 512-bit block (bytes 64..79 + pad) + the final SHA-256
// of the 32-byte digest, then compares against the LE target (MSW first).

__constant uint K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define BSIG1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SSIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static void transform(uint state[8], const uint w_in[16]) {
    uint w[64];
    for (int i = 0; i < 16; i++) w[i] = w_in[i];
    for (int i = 16; i < 64; i++)
        w[i] = SSIG1(w[i-2]) + w[i-7] + SSIG0(w[i-15]) + w[i-16];

    uint a=state[0],b=state[1],c=state[2],d=state[3];
    uint e=state[4],f=state[5],g=state[6],h=state[7];
    for (int i = 0; i < 64; i++) {
        uint t1 = h + BSIG1(e) + CH(e,f,g) + K[i] + w[i];
        uint t2 = BSIG0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static void sha256_32(const uint in_be[8], uint out[8]) {
    uint state[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    uint w[16];
    for (int i = 0; i < 8; i++) w[i]=in_be[i];
    w[8]=0x80000000u;
    for (int i = 9; i < 15; i++) w[i]=0;
    w[15]=256u;
    transform(state, w);
    for (int i = 0; i < 8; i++) out[i]=state[i];
}

static uint bswap32(uint x) {
    return (x >> 24) | ((x >> 8) & 0x0000ff00u) | ((x << 8) & 0x00ff0000u) | (x << 24);
}

/*
 * midstate: 8 BE SHA-256 state words after header[0..63]
 * tail_be:  3 BE words = header bytes 64..75 (ntime || nbits high)
 * nonce is appended as LE-in-header / BE-in-SHA word (bswap32)
 */
__kernel void search(__global const uint *midstate,
                     __global const uint *tail_be,
                     __global const uint *target,
                     const uint nstart,
                     __global uint *out)
{
    uint gid = get_global_id(0);
    uint nonce = nstart + gid;

    uint state[8];
    for (int i = 0; i < 8; i++) state[i] = midstate[i];

    uint w[16];
    w[0] = tail_be[0];
    w[1] = tail_be[1];
    w[2] = tail_be[2];
    w[3] = bswap32(nonce);
    w[4] = 0x80000000u;
    for (int i = 5; i < 15; i++) w[i] = 0;
    w[15] = 640u;
    transform(state, w);

    uint d2[8];
    sha256_32(state, d2);

    for (int i = 7; i >= 0; i--) {
        uint hw = bswap32(d2[i]);
        uint tw = target[i];
        if (hw < tw) break;
        if (hw > tw) return;
    }

    uint idx = atomic_inc(&out[0]);
    if (idx < 256u) {
        out[1 + idx] = nonce;
    }
}
