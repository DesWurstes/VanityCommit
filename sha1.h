#include <stddef.h>

typedef struct _SHA1_CTX {
	uint32_t s[5];
	unsigned char buf[64];
	uint64_t bytes;
} SHA1_CTX;

void SHA1_WRITE(SHA1_CTX *sha1_ctx, const unsigned char *data, size_t len);

void SHA1_NEW(SHA1_CTX *sha1_ctx);

void SHA1_COPY(SHA1_CTX *to, const SHA1_CTX *from);

void SHA1_FINALIZE(SHA1_CTX *sha1_ctx, unsigned char hash[20]);
