/*	$OpenBSD: md5.h,v 1.2 2012/12/05 23:20:15 deraadt Exp $	*/

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */

#ifndef _UTIL_MD5_H_
#define _UTIL_MD5_H_ 

#include <stdint.h>

#define	MD5_BLOCK_LENGTH		64
#define	MD5_DIGEST_LENGTH		16

typedef struct UTIL_MD5Context {
	uint32_t state[4];			/* state */
	uint64_t count;			/* number of bits, mod 2^64 */
	uint8_t buffer[MD5_BLOCK_LENGTH];	/* input buffer */
} UTIL_MD5_CTX;

void	 MD5Init(UTIL_MD5_CTX *);
void	 MD5Update(UTIL_MD5_CTX *, const uint8_t *, size_t)
		/*__attribute__((__bounded__(__string__,2,3)))*/;
void	 MD5Final(uint8_t [MD5_DIGEST_LENGTH], UTIL_MD5_CTX *)
		/*__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_LENGTH)))*/;
void	 MD5Transform(uint32_t [4], const uint8_t [MD5_BLOCK_LENGTH])
		/*__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_BLOCK_LENGTH)))*/;
void md5_sum(const void* key, size_t key_len, unsigned char* md5sum);
void print_md5(unsigned char* md5sum);
void transform_md5(unsigned char* src, char* dest);
unsigned get_hash_from_md5(unsigned char* md5sum);
size_t get_index_from_key(const void* key, size_t key_len);

int32_t cal_roll_check_sum(const char* start, size_t size);

#endif /* _UTIL_MD5_H_*/
