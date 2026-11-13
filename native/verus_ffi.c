/*
 * pcminer Verus FFI - mirrors phone stratum_verus hash path (PBaaS + V2.2).
 */
#include "verus_ffi.h"

#include "blake2b/blake2b.h"
#include "verushash/verus_hash.h"

#include <string.h>

#define VERUS_HEADER_SIZE 140

void mm_verus_hash_init(void)
{
	verus_hash_v2_init();
}

static void write_u64_le(uint8_t *p, uint64_t v)
{
	int i;
	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (8 * i));
}

static int is_pbaas(const uint8_t *sol, size_t sol_len)
{
	return sol && sol_len >= 156 && sol[0] > 6;
}

static int pbaas_embed(uint8_t *blob, size_t blob_len)
{
	uint8_t pre[196];
	uint8_t digest[32];
	uint8_t *sol;
	size_t sol_len;

	if (blob_len < VERUS_HEADER_SIZE + 156)
		return -1;
	sol = blob + VERUS_HEADER_SIZE;
	sol_len = blob_len - VERUS_HEADER_SIZE;
	memcpy(pre + 0, blob + 4, 32);
	memcpy(pre + 32, blob + 36, 32);
	memcpy(pre + 64, blob + 68, 32);
	memcpy(pre + 96, blob + 108, 32);
	memcpy(pre + 128, blob + 104, 4);
	if (sol_len >= 72)
		memcpy(pre + 132, sol + 8, 64);
	else
		memset(pre + 132, 0, 64);
	if (blake2b_personal(digest, 32, pre, sizeof(pre), "VerusDefaultHash",
			     16) != 0)
		return -1;
	memcpy(sol + 124, digest, 32);
	return 0;
}

static void pbaas_clear(uint8_t *blob, size_t blob_len)
{
	uint8_t *sol = blob + VERUS_HEADER_SIZE;
	size_t sol_len = blob_len - VERUS_HEADER_SIZE;
	memset(blob + 4, 0, 96);
	memset(blob + 104, 0, 4);
	memset(blob + 108, 0, 32);
	if (sol_len >= 72)
		memset(sol + 8, 0, 64);
}

int mm_verus_hash_work(uint8_t out[32], const uint8_t *blob, size_t blob_len,
		       uint64_t nonce)
{
	uint8_t scratch[2048];

	if (!out || !blob || blob_len < VERUS_HEADER_SIZE || blob_len > sizeof(scratch))
		return -1;
	memcpy(scratch, blob, blob_len);
	write_u64_le(scratch + 108 + 24, nonce);
	if (is_pbaas(scratch + VERUS_HEADER_SIZE, blob_len - VERUS_HEADER_SIZE)) {
		if (pbaas_embed(scratch, blob_len) != 0)
			return -1;
		pbaas_clear(scratch, blob_len);
	}
	verus_hash_v2_2(out, scratch, blob_len);
	return 0;
}
