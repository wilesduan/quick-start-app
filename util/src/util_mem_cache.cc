#include "util_mem_cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "util_md5.h"

#define INIT_BUCKET 128

#define CHECK_PARAM(cache, key, key_len)\
	if(NULL == cache || NULL == key || 0 == key_len)\
        return -1;
static void dummy_free(const void* )
{
}

static void util_destroy_cache_2(_cache_t* _cache)
{
	if(NULL == _cache)
	{
		return;
	}

	if(_cache->buckets != NULL)
	{
		for(size_t i = 0; i < _cache->num_bucket; ++i)
		{
			block_t* block = _cache->buckets[i].bucket;
			while(block)
			{
				block_t* next_block = block->next_block;
				block->free_fn(block->value);
				block = next_block;
			}
			_cache->buckets[i].bucket = NULL;
		}

		free(_cache->buckets);
		_cache->buckets = NULL;
	}

	free(_cache);
}

static _cache_t* util_create_cache_2(int bucket_size)
{
	_cache_t* _cache = (_cache_t*)malloc(sizeof(_cache_t));
	if(NULL == _cache)
	{
		return NULL;
	}

	_cache->buckets = (bucket_t*)calloc(bucket_size, sizeof(bucket_t));
	if(NULL == _cache->buckets)
	{
		free(_cache);
		return NULL;
	}

	_cache->num_bucket = bucket_size;
	_cache->clear_index = 0;
	_cache->num_items = 0;

	return _cache;
}

void util_destroy_cache(cache_t** ppcache)
{
	if(NULL == ppcache || NULL == *ppcache)
	{
		return;
	}

	cache_t* cache = *ppcache;
	util_destroy_cache_2(cache->cur_cache);
	util_destroy_cache_2(cache->next_cache);

	block_t* blocks = cache->alloc_blocks;
	while(blocks)
	{
		block_t* next_blocks = blocks->next_block;
		free(blocks);
		blocks = next_blocks;
	}

	free(cache);
	*ppcache = NULL;
}

cache_t* util_create_cache()
{
	cache_t* cache = (cache_t*)malloc(sizeof(cache_t));
	if(NULL == cache)
	{
		return NULL;
	}

	cache->cur_cache = NULL;
	cache->next_cache = NULL;
	cache->free_block = NULL;
	cache->alloc_blocks = NULL;
	cache->stat = EN_STAT_NORMAL;
	cache->num_items = 0;

	cache->cur_cache = util_create_cache_2(INIT_BUCKET);
	if(NULL == cache->cur_cache)
	{
		free(cache);
	}

	return cache;
}

static block_t* get_from_cache_t(_cache_t* cache, cache_param_t* param)
{
	unsigned index = (param->hash) & (cache->num_bucket -1);
	block_t* block = cache->buckets[index].bucket;
	while(block)
	{
		if(param->key_len == block->key_len && memcmp(param->md5, block->md5, MD5_LEN) == 0)
		{
			return block;
		}

		block = block->next_block;
	}

	return NULL;
}

static block_t* get_key_in_block(cache_t* cache, cache_param_t* param)
{
	unsigned index_in_cur = (param->hash)&(cache->cur_cache->num_bucket -1);
	if(index_in_cur >= cache->cur_cache->clear_index)
	{
		return get_from_cache_t(cache->cur_cache, param);
	}
	else if(cache->stat == EN_STAT_TRANSF)
	{
		return get_from_cache_t(cache->next_cache, param);
	}

	return NULL;
}

void set_block(block_t* block, cache_param_t* param)
{
	memcpy(block->md5, param->md5, MD5_LEN);
	block->key_len = param->key_len;
	block->value = param->value;
	block->free_fn = param->free_fn;
}

//static int reset_key(cache_t* cache, const void* key, size_t key_len, const void* value, fn_free_cache free_fn)
static int reset_key(cache_t* cache, cache_param_t* param)
{
	block_t* block = get_key_in_block(cache, param);
	if(NULL == block)
	{
		return -1;
	}

	if(param->value == block->value)
	{
		return 0;
	}
	
	printf("reset key: %s\n", (const char*)param->key);
	if(block->free_fn)
	{
		block->free_fn(block->value);
	}

	set_block(block, param);
	return 0;
}

static void put_key_2_cache_t(_cache_t* _cache, unsigned hash, block_t* block)
{
	unsigned index = hash &(_cache->num_bucket - 1);
	bucket_t& bucket = _cache->buckets[index];

	block->next_block = bucket.bucket;
	block->prev_block = NULL;
	block->bucket = &bucket;
	if(bucket.bucket)
	{
		bucket.bucket->prev_block = block;
	}

	bucket.bucket = block;
	bucket._cache = _cache;
	++bucket.num_block;

	++_cache->num_items;
	return;
}

static void reset_block(block_t* block)
{
	memset(block->md5, 0 , MD5_LEN);
	block->key_len = 0;
	block->value = NULL;
	block->free_fn = NULL;
	block->next_block = NULL;
	block->prev_block = NULL;
}

static block_t* get_free_block(cache_t* cache)
{
	block_t* block = NULL; 
	if(cache->free_block != NULL)
	{
		block = cache->free_block;
		cache->free_block = block->next_block;
		reset_block(block);
		return block;
	}

	static const int num_alloc = 128;
	block_t* blocks = (block_t*)calloc(num_alloc, sizeof(block_t));
	if(NULL == blocks)
	{
		return NULL;
	}

	blocks->next_block = cache->alloc_blocks;
	cache->alloc_blocks = blocks;

	for(int i = 2; i < num_alloc; ++i)
	{
		blocks[i].next_block = cache->free_block;
		cache->free_block = blocks + i;
	}

	block = blocks + 1;
	return block;
}

//static int put_key(cache_t* cache, const void* key, size_t key_len, const void* value, fn_free_cache free_fn)
static int put_key(cache_t* cache, cache_param_t* param)
{
	block_t* block = get_free_block(cache);
	if(NULL == block)
	{
		return -1;
	}

	set_block(block, param);

	unsigned index_in_cur = param->hash&(cache->cur_cache->num_bucket -1);

	++cache->num_items;
	if(cache->stat == EN_STAT_NORMAL || index_in_cur >= cache->cur_cache->clear_index)
	{
		put_key_2_cache_t(cache->cur_cache, param->hash, block);
		return 0;
	}

	put_key_2_cache_t(cache->next_cache, param->hash, block);
	return 0;
}

static void adapt_cache(cache_t* cache)
{
	if(cache->num_items < (cache->cur_cache->num_bucket<<2))
	{
		return;
	}

	if(NULL == cache->next_cache)
	{
		cache->next_cache = util_create_cache_2(cache->cur_cache->num_bucket<<1);
		if(NULL == cache->next_cache)
	    {
	    	return;
	    }
	}

	cache->stat = EN_STAT_TRANSF;
	size_t i = cache->cur_cache->clear_index;
	for(; i < cache->cur_cache->clear_index+4 && i < cache->cur_cache->num_bucket; ++i)
	{
		bucket_t& bucket = cache->cur_cache->buckets[i];
		block_t* block = bucket.bucket;
		while(block)
		{
			block_t* next_block = block->next_block;
			unsigned hash = *(unsigned*)(block->md5);
			if(block->key_len >= MD5_LEN){
				hash = get_hash_from_md5(block->md5);
			}

			put_key_2_cache_t(cache->next_cache, hash, block);

			--bucket.num_block;
			--cache->cur_cache->num_items;

			block = next_block;
		}
		cache->cur_cache->buckets[i].bucket = NULL;
	}

	cache->cur_cache->clear_index = i;
	if(cache->cur_cache->clear_index >= cache->cur_cache->num_bucket)
	{
		cache->stat = EN_STAT_NORMAL;
		util_destroy_cache_2(cache->cur_cache);
		cache->cur_cache = cache->next_cache;
		cache->next_cache = NULL;
	}
}

static void gen_param(const void* key, size_t key_len, const void* value, fn_free_cache free_fn, cache_param_t* param)
{
	if(key_len<MD5_LEN){
		memset(param->md5, 0, MD5_LEN);
		memcpy(param->md5, key, key_len);
		param->hash = *(unsigned*)(param->md5);
	}else{
		md5_sum(key, key_len, param->md5);
		param->hash = get_hash_from_md5(param->md5);
	}

	param->key = key;
	param->key_len = key_len;
	param->value = value;
	param->free_fn = free_fn;
}

int util_set_item(cache_t* cache, const void* key, size_t key_len, const void* value, fn_free_cache free_fn) 
{
	CHECK_PARAM(cache, key, key_len);
	if(NULL == free_fn)
	{
		free_fn = dummy_free;
	}

	adapt_cache(cache);

	cache_param_t param;
	gen_param(key, key_len, value, free_fn, &param);

	int rc = reset_key(cache, &param);
	if(rc == 0)
	{
		return 0;
	}

	return put_key(cache, &param);
}

const void* util_get_item(cache_t* cache, const void* key, size_t key_len)
{
	if(NULL == cache || NULL == key || 0 == key_len)
	{
		return NULL;
	}

	unsigned char md5sum[MD5_LEN];
	md5_sum(key, key_len, md5sum);
	cache_param_t param;
	gen_param(key, key_len, NULL, NULL, &param);

	block_t* block = get_key_in_block(cache, &param);
	if(NULL == block)
	{
		return NULL;
	}

	return block->value;
}

int util_del_item(cache_t* cache, const void* key, size_t key_len)
{
	CHECK_PARAM(cache, key, key_len);

	cache_param_t param;
	gen_param(key, key_len, NULL, NULL, &param);
	block_t* block = get_key_in_block(cache, &param);
	if(NULL == block)
	{
		return 0;
	}

	if(block->free_fn)
	{
		block->free_fn(block->value);
		block->value = NULL;
		block->free_fn = NULL;
	}

	bucket_t* bucket = (bucket_t*)(block->bucket);
	_cache_t* _cache = (_cache_t*)(bucket->_cache);

	block_t* prev_block = block->prev_block;
	block_t* next_block = block->next_block;

	if(prev_block)
	{
		prev_block->next_block = next_block;
	}
	else{
		bucket->bucket = next_block;
	}

	if(next_block)
	{
		next_block->prev_block = prev_block;
	}

	block->prev_block = NULL;

	block->next_block = cache->free_block;
	cache->free_block = block;

	--cache->num_items;
	--_cache->num_items;
	--bucket->num_block;
	return 0;
}
