#ifndef _UTIL_MEM_CACHE_H_
#define _UTIL_MEM_CACHE_H_

#define MD5_LEN 16
#include <stdlib.h>

typedef void(*fn_free_cache)(const void*);

enum cache_stat
{
	EN_STAT_NORMAL,
	EN_STAT_TRANSF,
};

typedef struct block_t
{
	unsigned char md5[MD5_LEN];
	size_t key_len;
	const void* value;
	fn_free_cache free_fn;
	block_t* next_block;
	block_t* prev_block;
	void* bucket;
}block_t;

typedef struct
{
	unsigned char md5[MD5_LEN];
	unsigned hash;
	const void* key;
	size_t key_len;
	const void* value;
	fn_free_cache free_fn;
}cache_param_t;

typedef struct
{
	block_t* bucket;
	size_t num_block;
	void* _cache;
}bucket_t;

typedef struct
{
	bucket_t* buckets;
	size_t num_bucket;
	size_t clear_index;

	size_t num_items;
}_cache_t;

typedef struct
{
	_cache_t* cur_cache;
	_cache_t* next_cache;
	block_t* free_block;
	block_t* alloc_blocks;
	cache_stat stat;

	size_t num_items;
}cache_t;

cache_t* util_create_cache();
void util_destroy_cache(cache_t** ppcache);

int util_set_item(cache_t* cache, const void* key, size_t key_len, const void* value, fn_free_cache free_fn);
const void* util_get_item(cache_t* cache, const void* key, size_t key_len);
int util_del_item(cache_t* cache, const void* key, size_t key_len);

#endif //_UTIL_MEM_CACHE_H_

