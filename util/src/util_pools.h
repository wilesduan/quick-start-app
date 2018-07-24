#ifndef _WILES_POOL_H_
#define _WILES_POOL_H_

#include "list.h"
#include <unistd.h>
#include <stdint.h>

#define util_align(d, a) (((d)+(a-1))&~(a-1))
#define util_align_ptr(p, a)  (char*)(((uintptr_t)(p) + ((uintptr_t)a-1)) & ~((uintptr_t)a-1))
#define UTIL_MAX_ALLOC_FROM_POOL (sysconf(_SC_PAGESIZE)- 1)
#define UTIL_DEFAULT_POOL_SIZE (16*1024)
#define UTIL_POOL_ALIGNMENT 16
#define UTIL_ALIGNMENT sizeof(unsigned long)


#define UTIL_MIN_POOL_SIZE util_align((sizeof(util_pool_t) + 2 * sizeof(util_pool_large_t)), UTIL_POOL_ALIGNMENT)

struct util_pool_large_t
{
	struct util_pool_large_t* next;
	void* alloc;
};

struct util_pool_data_t
{
	char* last;
	char* end;
	char* next;
	unsigned failed;
};

struct util_pool_t
{
	util_pool_data_t d;
	size_t max;
	util_pool_t* current;
	util_pool_large_t* large;
};

void* util_memalign(size_t alignment, size_t size);

struct util_pool_t* util_pool_create(size_t size);
void util_pool_destroy(struct util_pool_t* pool);

void* util_palloc(struct util_pool_t* pool, size_t size);
void* util_pnalloc(struct util_pool_t* pool, size_t size);
void* util_pcalloc(struct util_pool_t* pool, size_t size);
void* util_pmemalign(struct util_pool_t* pool, size_t size, size_t alignment);
int util_pfree(util_pool_t* pool, void* p);

void util_reset_pool(util_pool_t* pool);

#endif//_WILES_POOL_H_
