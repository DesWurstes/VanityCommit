// The MIT License (MIT)
//
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2009-2018 Bitcoin Developers
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#	ifdef __GNUC__
#		if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#			define LITTLE_ENDIAN
#		elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#			define BIG_ENDIAN
#		endif // __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#	elif defined(_WIN32)
#		include <Windows.h>
#		if REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#			define LITTLE_ENDIAN
#		elif REG_DWORD == REG_DWORD_BIG_ENDIANN
#			define BIG_ENDIAN
#		endif // REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#	elif defined(__linux__)
#		include <endian.h>
#		define HAS_FUNC
#		if __BYTE_ORDER == __LITTLE_ENDIAN
#			define LITTLE_ENDIAN
#		elif __BYTE_ORDER == __BIG_ENDIAN
#			define BIG_ENDIAN
#		endif
#		include <byteswap.h>
#	endif // defined(__linux__)
#endif // !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#  warning Cannot determine endianness! Assuming it is little endian. To ignore\
this, add #define LITTLE_ENDIAN or BIG_ENDIAN, or pass -DLITTLE_ENDIAN or \
-DBIG_ENDIAN to the compiler.
#	define LITTLE_ENDIAN
#endif

#ifndef HAS_FUNC
static inline uint32_t bswap_32(uint32_t x) {
	return (((x & 0xff000000U) >> 24) | ((x & 0x00ff0000U) >> 8) |
		((x & 0x0000ff00U) << 8) | ((x & 0x000000ffU) << 24));
}

static inline uint64_t bswap_64(uint64_t x) {
	return (((x & 0xff00000000000000ull) >> 56) |
		((x & 0x00ff000000000000ull) >> 40) |
		((x & 0x0000ff0000000000ull) >> 24) |
		((x & 0x000000ff00000000ull) >> 8) |
		((x & 0x00000000ff000000ull) << 8) |
		((x & 0x0000000000ff0000ull) << 24) |
		((x & 0x000000000000ff00ull) << 40) |
		((x & 0x00000000000000ffull) << 56));
}
#	ifdef LITTLE_ENDIAN
static inline uint32_t htobe32(uint32_t host_32bits) {
	return bswap_32(host_32bits);
}

static inline uint64_t htobe64(uint64_t host_64bits) {
	return bswap_64(host_64bits);
}
#	else
static inline uint32_t htobe32(uint32_t host_32bits) { return host_32bits; }

static inline uint64_t htobe64(uint64_t host_64bits) { return host_64bits; }

#	endif
#endif

static inline void WriteBE32(unsigned char *ptr, uint32_t x) {
	uint32_t v = htobe32(x);
	memcpy(ptr, (char *) &v, 4);
}

static inline void WriteBE64(unsigned char *ptr, uint64_t x) {
	uint64_t v = htobe64(x);
	memcpy(ptr, (char *) &v, 8);
}

static inline uint32_t ReadBE32(const unsigned char *ptr) {
	return ((uint32_t) ptr[0] << 24 | (uint32_t) ptr[1] << 16 |
		(uint32_t) ptr[2] << 8 | (uint32_t) ptr[3]);
}

/** One round of SHA-1. */
static inline void Round(uint32_t a, uint32_t *b, uint32_t c, uint32_t d,
	uint32_t *e, uint32_t f, uint32_t k, uint32_t w) {
	(void) c;
	(void) d;
	*e += ((a << 5) | (a >> 27)) + f + k + w;
	*b = (*b << 30) | (*b >> 2);
}

static inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d) {
	return d ^ (b & (c ^ d));
}
static inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d) {
	return b ^ c ^ d;
}
static inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d) {
	return (b & c) | (d & (b | c));
}

static inline uint32_t left(uint32_t x) { return (x << 1) | (x >> 31); }

const uint32_t k1 = 0x5A827999ul;
const uint32_t k2 = 0x6ED9EBA1ul;
const uint32_t k3 = 0x8F1BBCDCul;
const uint32_t k4 = 0xCA62C1D6ul;

/** Perform a SHA-1 transformation, processing a 64-byte chunk. */
static void Transform(uint32_t *s, const unsigned char *chunk) {
	uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
	uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13,
		w14, w15;

	Round(a, &b, c, d, &e, f1(b, c, d), k1, w0 = ReadBE32(chunk + 0));
	Round(e, &a, b, c, &d, f1(a, b, c), k1, w1 = ReadBE32(chunk + 4));
	Round(d, &e, a, b, &c, f1(e, a, b), k1, w2 = ReadBE32(chunk + 8));
	Round(c, &d, e, a, &b, f1(d, e, a), k1, w3 = ReadBE32(chunk + 12));
	Round(b, &c, d, e, &a, f1(c, d, e), k1, w4 = ReadBE32(chunk + 16));
	Round(a, &b, c, d, &e, f1(b, c, d), k1, w5 = ReadBE32(chunk + 20));
	Round(e, &a, b, c, &d, f1(a, b, c), k1, w6 = ReadBE32(chunk + 24));
	Round(d, &e, a, b, &c, f1(e, a, b), k1, w7 = ReadBE32(chunk + 28));
	Round(c, &d, e, a, &b, f1(d, e, a), k1, w8 = ReadBE32(chunk + 32));
	Round(b, &c, d, e, &a, f1(c, d, e), k1, w9 = ReadBE32(chunk + 36));
	Round(a, &b, c, d, &e, f1(b, c, d), k1, w10 = ReadBE32(chunk + 40));
	Round(e, &a, b, c, &d, f1(a, b, c), k1, w11 = ReadBE32(chunk + 44));
	Round(d, &e, a, b, &c, f1(e, a, b), k1, w12 = ReadBE32(chunk + 48));
	Round(c, &d, e, a, &b, f1(d, e, a), k1, w13 = ReadBE32(chunk + 52));
	Round(b, &c, d, e, &a, f1(c, d, e), k1, w14 = ReadBE32(chunk + 56));
	Round(a, &b, c, d, &e, f1(b, c, d), k1, w15 = ReadBE32(chunk + 60));

	Round(e, &a, b, c, &d, f1(a, b, c), k1, w0 = left(w0 ^ w13 ^ w8 ^ w2));
	Round(d, &e, a, b, &c, f1(e, a, b), k1, w1 = left(w1 ^ w14 ^ w9 ^ w3));
	Round(c, &d, e, a, &b, f1(d, e, a), k1, w2 = left(w2 ^ w15 ^ w10 ^ w4));
	Round(b, &c, d, e, &a, f1(c, d, e), k1, w3 = left(w3 ^ w0 ^ w11 ^ w5));
	Round(a, &b, c, d, &e, f2(b, c, d), k2, w4 = left(w4 ^ w1 ^ w12 ^ w6));
	Round(e, &a, b, c, &d, f2(a, b, c), k2, w5 = left(w5 ^ w2 ^ w13 ^ w7));
	Round(d, &e, a, b, &c, f2(e, a, b), k2, w6 = left(w6 ^ w3 ^ w14 ^ w8));
	Round(c, &d, e, a, &b, f2(d, e, a), k2, w7 = left(w7 ^ w4 ^ w15 ^ w9));
	Round(b, &c, d, e, &a, f2(c, d, e), k2, w8 = left(w8 ^ w5 ^ w0 ^ w10));
	Round(a, &b, c, d, &e, f2(b, c, d), k2, w9 = left(w9 ^ w6 ^ w1 ^ w11));
	Round(e, &a, b, c, &d, f2(a, b, c), k2,
		w10 = left(w10 ^ w7 ^ w2 ^ w12));
	Round(d, &e, a, b, &c, f2(e, a, b), k2,
		w11 = left(w11 ^ w8 ^ w3 ^ w13));
	Round(c, &d, e, a, &b, f2(d, e, a), k2,
		w12 = left(w12 ^ w9 ^ w4 ^ w14));
	Round(b, &c, d, e, &a, f2(c, d, e), k2,
		w13 = left(w13 ^ w10 ^ w5 ^ w15));
	Round(a, &b, c, d, &e, f2(b, c, d), k2,
		w14 = left(w14 ^ w11 ^ w6 ^ w0));
	Round(e, &a, b, c, &d, f2(a, b, c), k2,
		w15 = left(w15 ^ w12 ^ w7 ^ w1));

	Round(d, &e, a, b, &c, f2(e, a, b), k2, w0 = left(w0 ^ w13 ^ w8 ^ w2));
	Round(c, &d, e, a, &b, f2(d, e, a), k2, w1 = left(w1 ^ w14 ^ w9 ^ w3));
	Round(b, &c, d, e, &a, f2(c, d, e), k2, w2 = left(w2 ^ w15 ^ w10 ^ w4));
	Round(a, &b, c, d, &e, f2(b, c, d), k2, w3 = left(w3 ^ w0 ^ w11 ^ w5));
	Round(e, &a, b, c, &d, f2(a, b, c), k2, w4 = left(w4 ^ w1 ^ w12 ^ w6));
	Round(d, &e, a, b, &c, f2(e, a, b), k2, w5 = left(w5 ^ w2 ^ w13 ^ w7));
	Round(c, &d, e, a, &b, f2(d, e, a), k2, w6 = left(w6 ^ w3 ^ w14 ^ w8));
	Round(b, &c, d, e, &a, f2(c, d, e), k2, w7 = left(w7 ^ w4 ^ w15 ^ w9));
	Round(a, &b, c, d, &e, f3(b, c, d), k3, w8 = left(w8 ^ w5 ^ w0 ^ w10));
	Round(e, &a, b, c, &d, f3(a, b, c), k3, w9 = left(w9 ^ w6 ^ w1 ^ w11));
	Round(d, &e, a, b, &c, f3(e, a, b), k3,
		w10 = left(w10 ^ w7 ^ w2 ^ w12));
	Round(c, &d, e, a, &b, f3(d, e, a), k3,
		w11 = left(w11 ^ w8 ^ w3 ^ w13));
	Round(b, &c, d, e, &a, f3(c, d, e), k3,
		w12 = left(w12 ^ w9 ^ w4 ^ w14));
	Round(a, &b, c, d, &e, f3(b, c, d), k3,
		w13 = left(w13 ^ w10 ^ w5 ^ w15));
	Round(e, &a, b, c, &d, f3(a, b, c), k3,
		w14 = left(w14 ^ w11 ^ w6 ^ w0));
	Round(d, &e, a, b, &c, f3(e, a, b), k3,
		w15 = left(w15 ^ w12 ^ w7 ^ w1));

	Round(c, &d, e, a, &b, f3(d, e, a), k3, w0 = left(w0 ^ w13 ^ w8 ^ w2));
	Round(b, &c, d, e, &a, f3(c, d, e), k3, w1 = left(w1 ^ w14 ^ w9 ^ w3));
	Round(a, &b, c, d, &e, f3(b, c, d), k3, w2 = left(w2 ^ w15 ^ w10 ^ w4));
	Round(e, &a, b, c, &d, f3(a, b, c), k3, w3 = left(w3 ^ w0 ^ w11 ^ w5));
	Round(d, &e, a, b, &c, f3(e, a, b), k3, w4 = left(w4 ^ w1 ^ w12 ^ w6));
	Round(c, &d, e, a, &b, f3(d, e, a), k3, w5 = left(w5 ^ w2 ^ w13 ^ w7));
	Round(b, &c, d, e, &a, f3(c, d, e), k3, w6 = left(w6 ^ w3 ^ w14 ^ w8));
	Round(a, &b, c, d, &e, f3(b, c, d), k3, w7 = left(w7 ^ w4 ^ w15 ^ w9));
	Round(e, &a, b, c, &d, f3(a, b, c), k3, w8 = left(w8 ^ w5 ^ w0 ^ w10));
	Round(d, &e, a, b, &c, f3(e, a, b), k3, w9 = left(w9 ^ w6 ^ w1 ^ w11));
	Round(c, &d, e, a, &b, f3(d, e, a), k3,
		w10 = left(w10 ^ w7 ^ w2 ^ w12));
	Round(b, &c, d, e, &a, f3(c, d, e), k3,
		w11 = left(w11 ^ w8 ^ w3 ^ w13));
	Round(a, &b, c, d, &e, f2(b, c, d), k4,
		w12 = left(w12 ^ w9 ^ w4 ^ w14));
	Round(e, &a, b, c, &d, f2(a, b, c), k4,
		w13 = left(w13 ^ w10 ^ w5 ^ w15));
	Round(d, &e, a, b, &c, f2(e, a, b), k4,
		w14 = left(w14 ^ w11 ^ w6 ^ w0));
	Round(c, &d, e, a, &b, f2(d, e, a), k4,
		w15 = left(w15 ^ w12 ^ w7 ^ w1));

	Round(b, &c, d, e, &a, f2(c, d, e), k4, w0 = left(w0 ^ w13 ^ w8 ^ w2));
	Round(a, &b, c, d, &e, f2(b, c, d), k4, w1 = left(w1 ^ w14 ^ w9 ^ w3));
	Round(e, &a, b, c, &d, f2(a, b, c), k4, w2 = left(w2 ^ w15 ^ w10 ^ w4));
	Round(d, &e, a, b, &c, f2(e, a, b), k4, w3 = left(w3 ^ w0 ^ w11 ^ w5));
	Round(c, &d, e, a, &b, f2(d, e, a), k4, w4 = left(w4 ^ w1 ^ w12 ^ w6));
	Round(b, &c, d, e, &a, f2(c, d, e), k4, w5 = left(w5 ^ w2 ^ w13 ^ w7));
	Round(a, &b, c, d, &e, f2(b, c, d), k4, w6 = left(w6 ^ w3 ^ w14 ^ w8));
	Round(e, &a, b, c, &d, f2(a, b, c), k4, w7 = left(w7 ^ w4 ^ w15 ^ w9));
	Round(d, &e, a, b, &c, f2(e, a, b), k4, w8 = left(w8 ^ w5 ^ w0 ^ w10));
	Round(c, &d, e, a, &b, f2(d, e, a), k4, w9 = left(w9 ^ w6 ^ w1 ^ w11));
	Round(b, &c, d, e, &a, f2(c, d, e), k4,
		w10 = left(w10 ^ w7 ^ w2 ^ w12));
	Round(a, &b, c, d, &e, f2(b, c, d), k4,
		w11 = left(w11 ^ w8 ^ w3 ^ w13));
	Round(e, &a, b, c, &d, f2(a, b, c), k4,
		w12 = left(w12 ^ w9 ^ w4 ^ w14));
	Round(d, &e, a, b, &c, f2(e, a, b), k4, left(w13 ^ w10 ^ w5 ^ w15));
	Round(c, &d, e, a, &b, f2(d, e, a), k4, left(w14 ^ w11 ^ w6 ^ w0));
	Round(b, &c, d, e, &a, f2(c, d, e), k4, left(w15 ^ w12 ^ w7 ^ w1));

	s[0] += a;
	s[1] += b;
	s[2] += c;
	s[3] += d;
	s[4] += e;
}

////// SHA1

typedef struct _SHA1_CTX {
	uint32_t s[5];
	unsigned char buf[64];
	uint64_t bytes;
} SHA1_CTX;

void SHA1_NEW(SHA1_CTX *sha1_ctx) {
	sha1_ctx->bytes = 0;
	sha1_ctx->s[0] = 0x67452301ul;
	sha1_ctx->s[1] = 0xEFCDAB89ul;
	sha1_ctx->s[2] = 0x98BADCFEul;
	sha1_ctx->s[3] = 0x10325476ul;
	sha1_ctx->s[4] = 0xC3D2E1F0ul;
}

void SHA1_WRITE(SHA1_CTX *sha1_ctx, const unsigned char *data, size_t len) {
	const unsigned char *end = data + len;
	size_t bufsize = sha1_ctx->bytes % 64;
	if (bufsize && bufsize + len >= 64) {
		memcpy(sha1_ctx->buf + bufsize, data, 64 - bufsize);
		sha1_ctx->bytes += 64 - bufsize;
		data += 64 - bufsize;
		Transform(sha1_ctx->s, sha1_ctx->buf);
		bufsize = 0;
	}
	while (end >= data + 64) {
		Transform(sha1_ctx->s, data);
		sha1_ctx->bytes += 64;
		data += 64;
	}
	if (end > data) {
		memcpy(sha1_ctx->buf + bufsize, data, end - data);
		sha1_ctx->bytes += end - data;
	}
}

void SHA1_COPY(SHA1_CTX *to, const SHA1_CTX *from) {
	memcpy(to->s, from->s, 5 * sizeof(uint32_t));
	memcpy(to->buf, from->buf, 64);
	to->bytes = from->bytes;
}

void SHA1_FINALIZE(SHA1_CTX *sha1_ctx, unsigned char hash[20]) {
	static const unsigned char pad[64] = {0x80};
	unsigned char sizedesc[8];
	WriteBE64(sizedesc, sha1_ctx->bytes << 3);
	SHA1_WRITE(sha1_ctx, pad, 1 + ((119 - (sha1_ctx->bytes % 64)) % 64));
	SHA1_WRITE(sha1_ctx, sizedesc, 8);
	WriteBE32(hash, sha1_ctx->s[0]);
	WriteBE32(hash + 4, sha1_ctx->s[1]);
	WriteBE32(hash + 8, sha1_ctx->s[2]);
	WriteBE32(hash + 12, sha1_ctx->s[3]);
	WriteBE32(hash + 16, sha1_ctx->s[4]);
}
