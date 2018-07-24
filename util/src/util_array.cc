#include <string.h>
#include "util_array.h"
#include "util_pools.h"

struct util_array_t* util_array_create(struct util_pool_t* pool, unsigned init_max_elts)
{
    if(NULL == pool)
    {
        return NULL;
    }
    
    if(0 == init_max_elts)
    {
        init_max_elts = 10;
    }
    
    util_array_t* array = (util_array_t*)util_pcalloc(pool, sizeof(util_array_t));
    if(NULL == array)
    {
        return NULL;
    }
    
    array->pointer_elts = (void**)util_pcalloc(pool, sizeof(void*)*init_max_elts);
    if(NULL == array->pointer_elts)
    {
        return NULL;
    }
    
    array->num_elts = 0;
    array->max_elts = init_max_elts;
    array->pool = pool;

    return array;
}

static int util_expand_array(util_array_t* array)
{
	void** pointers = (void**)util_pcalloc(array->pool, 2*array->max_elts*sizeof(void*));
	if(NULL == pointers)
	{
		return -1;
	}
	else
	{
		memcpy((void*)pointers, (void*)(array->pointer_elts), array->max_elts*sizeof(void*));
		array->pointer_elts = pointers;
		array->max_elts *= 2;
	}

	return 0;
}

int util_array_add_elt(util_array_t* array, const char* buff, int len)
{
    if(NULL == array)
    {
        //TODO log
        return 0;
    }

    if(array->num_elts >= array->max_elts && util_expand_array(array))
	{
		return -1;
	}

    if(NULL == buff || 0 == len)
    {
        array->pointer_elts[array->num_elts] = NULL;
        ++array->num_elts;
        return 0;
    }

    void* elt = util_pcalloc(array->pool, len+1);
    if(NULL == elt)
    {
        //TODO log
        return -2;
    }

    memcpy(elt, buff, len);
    ((char*)elt)[len] = 0;
    array->pointer_elts[array->num_elts] = elt;
    ++array->num_elts;

    return 0;
}

void util_array_remove(util_array_t* array, unsigned index)
{
	if(NULL == array)
	{
		return;
	}

	if(index >= array->num_elts)
	{
		return;
	}

	array->pointer_elts[index] = NULL;
	--array->num_elts;

	if(index == array->num_elts)
	{
		return;
	}

	array->pointer_elts[index] = array->pointer_elts[array->num_elts];
	array->pointer_elts[array->num_elts] = NULL;
}

void* util_array_at(const util_array_t* array, unsigned index)
{
    if(index >= array->num_elts)
    {
        return NULL;
    }

    return (void*)(array->pointer_elts[index]);
}

int util_array_zerocopy_add_elt(util_array_t* array, void* elt)
{
	if(NULL == array)
	{
		return -1;
	}

	if(array->num_elts >= array->max_elts && util_expand_array(array))
	{
		return -2;
	}

	array->pointer_elts[array->num_elts++] = elt;
	return 0;
}

void util_array_zerocopy_remove(util_array_t* array, unsigned index)
{
	util_array_remove(array, index);
}
