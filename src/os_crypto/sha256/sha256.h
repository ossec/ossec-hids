#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

typedef struct {
	uint8_t data[64];
	uint32_t datalen;
	unsigned long long bitlen;
	uint32_t state[8];
} SHA256_CTX;

void os_SHA256_Init(SHA256_CTX *ctx);
void os_SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void os_SHA256_Final(uint8_t hash[], SHA256_CTX *ctx);

#endif
