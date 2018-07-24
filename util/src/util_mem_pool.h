#ifndef UTIL_MEM_POOL_H
#define UTIL_MEM_POOL_H

#include "util_pools.h"
#include "util_array.h"

#define util_get_block_of_type(pool, type) (type*)util_get_block_from_pool(pool);

typedef struct
{
	util_pool_t* pool;
	util_array_t* free_blocks;
	size_t block_size;
}mem_pool_t;

mem_pool_t* util_create_mem_pool(size_t block_size);
void util_destroy_mem_pool(mem_pool_t* pool);
void* util_get_block_from_pool(mem_pool_t* pool);
void util_recycle_block_to_pool(mem_pool_t* pool, void* block);
#endif//UTIL_MEM_POOL_H

