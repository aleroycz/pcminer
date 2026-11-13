/* Thin VerusHash 2.2 + PBaaS helpers for pcminer CPU sweep. */
#ifndef PCMINER_VERUS_FFI_H
#define PCMINER_VERUS_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void mm_verus_hash_init(void);

/* Hash blob after applying 8-byte LE nonce at header[132..139]. */
int mm_verus_hash_work(uint8_t out[32], const uint8_t *blob, size_t blob_len,
		       uint64_t nonce);

#ifdef __cplusplus
}
#endif

#endif
