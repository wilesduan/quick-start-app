#include "util_mem_pool.h"
#define K_NUM_BLOCK_PER_ALLOC 20

mem_pool_t* util_create_mem_pool(size_t block_size)
{
	if(block_size == 0)
	{
		return NULL;
	}

	struct util_pool_t* pool = util_pool_create(block_size*K_NUM_BLOCK_PER_ALLOC);
	if(NULL == pool)
	{
		return NULL;
	}

	mem_pool_t* mem_pool = (mem_pool_t*)util_palloc(pool, sizeof(mem_pool_t));
	if(NULL == mem_pool)
	{
		util_pool_destroy(pool);
		return NULL;
	}

	util_array_t* array = util_array_create(pool, K_NUM_BLOCK_PER_ALLOC);
	if(NULL == array)
	{
		util_pool_destroy(pool);
		return NULL;
	}

	mem_pool->pool = pool;
	mem_pool->free_blocks = array;
	mem_pool->block_size = block_size;

	return mem_pool;
}

void util_destroy_mem_pool(mem_pool_t* pool)
{
	util_pool_destroy(pool->pool);
}

void* util_get_block_from_pool(mem_pool_t* pool)
{
	if(NULL == pool)
	{
		return NULL;
	}

	void* block = NULL;
	if(pool->free_blocks->num_elts > 0)
	{
		block = util_array_at(pool->free_blocks, 0);
		util_array_zerocopy_remove(pool->free_blocks, 0);
		return block;
	}
	
	block = util_palloc(pool->pool, pool->block_size);
	return block;
}

void util_recycle_block_to_pool(mem_pool_t* pool, void* block)
{
	if(NULL == pool || NULL == block)
	{
		return;
	}
	//TODO check block is in pool

	util_array_zerocopy_add_elt(pool->free_blocks, block);
	return;
}
