#include "util_pools.h"

#include <stdlib.h>
#include <strings.h>
#include <stdio.h>

static void* util_palloc_block(util_pool_t* pool, size_t size);
static void* util_palloc_large(util_pool_t* pool, size_t size);

void* util_memalign(size_t alignment, size_t size)
{
	void* p;
	int err;

	err = posix_memalign(&p, alignment, size);
	if(err)
	{
		return NULL;
	}

	//printf("%x ---- %x\n", p, (p+size));

	return p;
}

struct util_pool_t* util_pool_create(size_t size)
{
	if(size >= 10*1024*1024)
	{
		return NULL;
	}

	size += sizeof(util_pool_t);
	util_pool_t* p;
	p =(util_pool_t*) util_memalign(UTIL_POOL_ALIGNMENT, size);
	if(NULL == p)
	{
		return NULL;
	}

	p->d.last = (char*)p+sizeof(util_pool_t);
	p->d.end = (char*)p + size;
	p->d.next = NULL;
	p->d.failed = 0;

	size = size - sizeof(util_pool_t);
	p->max = (size < (size_t)UTIL_MAX_ALLOC_FROM_POOL)?size:UTIL_MAX_ALLOC_FROM_POOL;

	p->current = p;
	p->large = NULL;

	return p;
}

void util_pool_destroy(struct util_pool_t* pool)
{
	if(NULL == pool)
	{
		return;
	}
	
	util_pool_t* p, *n;
	util_pool_large_t* l;

	for(l = pool->large; l; l = l->next)
	{
		if(l->alloc)
		{
			free(l->alloc);
		}
	}

	for(p = pool, n = (util_pool_t*)(pool->d.next); ; p = n, n=(util_pool_t*)(n->d.next))
	{
		free(p);
		if(NULL == n)
		{
			break;
		}
	}
}

void* util_palloc(struct util_pool_t* pool, size_t size)
{
	char* m;
	util_pool_t* p;

	if(size <= pool->max)
	{
		p = pool->current;

		do
		{
			m = util_align_ptr(p->d.last, UTIL_ALIGNMENT);

			//printf("before alloc:%d\n", p->d.end-m);
			if((size_t)(p->d.end) >= (size_t)(m+size))
			{
				p->d.last = m + size;
				//printf("alloc from here:%d rest:%d\n", size, p->d.end - p->d.last);
				return m;
			}

			p = (util_pool_t*)(p->d.next);
		}while(p);
			
		return util_palloc_block(pool, size);
	}

	return util_palloc_large(pool, size);
}

void* util_pnalloc(struct util_pool_t* pool, size_t size)
{
	char* m;
	util_pool_t* p;

	if(size <= pool->max)
	{
		p = pool->current;

		do
		{
			m = p->d.last;

			if((size_t)(p->d.end) >= (size_t)(m+size))
			{
				p->d.last = m + size;
				return m;
			}

			p = (util_pool_t*)(p->d.next);
		}while(p);

		return util_palloc_block(pool, size);
	}

	return util_palloc_large(pool, size);
}

static void* util_palloc_block(util_pool_t* pool, size_t size)
{
	//printf("alloc a new block\n");
	char* m;
	size_t psize;
	struct util_pool_t *p, *new_pool, *current;

	psize = (size_t)(pool->d.end - (char*)pool);
	m = (char*)util_memalign(UTIL_POOL_ALIGNMENT, psize);
	if(NULL == m)
	{
		return NULL;
	}

	new_pool = (struct util_pool_t*)m;

	new_pool->d.end = m + psize;
	new_pool->d.next = NULL;
	new_pool->d.failed = 0;

	m += sizeof(util_pool_data_t);
	m = util_align_ptr(m, UTIL_ALIGNMENT);
	new_pool->d.last = m + size;

	current = pool->current;
	for(p = current; p->d.next; p = (util_pool_t*)(p->d.next))
	{
		if(p->d.failed++ > 4)
		{
			current = (util_pool_t*)(p->d.next);
		}
	}

	p->d.next = (char*)new_pool;
	pool->current = current?current:new_pool;

	return m;
}

static void* util_palloc_large(util_pool_t* pool, size_t size)
{
	//printf("alloc a large block\n");
	void* p;
	unsigned n;
	util_pool_large_t* large;

	p = malloc(size);
	if(NULL == p)
	{
		return NULL;
	}

	n = 0;

	for(large = pool->large; large; large = large->next)
	{
		if(NULL == large->alloc)
		{
			large->alloc = p;
			return p;
		}

		if(n++ > 3)
		{
			break;
		}
	}

	large = (util_pool_large_t*)util_palloc(pool, sizeof(util_pool_large_t));
	if(NULL == large)
	{
		free(p);
		return NULL;
	}

	large->alloc = p;
	large->next = pool->large;
	pool->large = large;
	return p;
}

void* util_pmemalign(struct util_pool_t* pool, size_t size, size_t alignment)
{
	void* p;
	util_pool_large_t* large;

	p = util_memalign(alignment, size);
	if(NULL == p)
	{
		return NULL;
	}

	large = (util_pool_large_t*)util_palloc(pool, sizeof(util_pool_large_t));
	if(NULL == large)
	{
		free(p);
		return NULL;
	}

	large->alloc = p;
	large->next = pool->large;
	pool->large = large;

	return p;
}

int util_pfree(util_pool_t* pool, void* p)
{
	util_pool_large_t* l;
	for(l = pool->large; l; l = l->next)
	{
		if(p == l->alloc)
		{
			free(l->alloc);
			l->alloc = NULL;
			return 0;
		}
	}

	return -1;
}

void* util_pcalloc(struct util_pool_t* pool, size_t size)
{
	void* p = util_palloc(pool, size);
	if(p)
	{
		bzero(p, size);
	}

	return p;
}

void util_reset_pool(struct util_pool_t* pool)
{
	struct util_pool_t* p;
	struct util_pool_large_t* l;

	for(l = pool->large; l; l = (struct util_pool_large_t*)(l->next))
	{
		if(l->alloc)
		{
			free(l->alloc);
		}
	}

	pool->large = NULL;

	for(p = pool; p; p = (struct util_pool_t*)(p->d.next))
	{
		p->d.last = (char*)p + sizeof(util_pool_t);
		p->d.failed = 0;
	}

	pool->current = pool;
}

