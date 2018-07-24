#ifndef _UTIL_ARRAY_H_
#define _UTIL_ARRAY_H_
struct util_pool_t;
struct util_array_t
{
    void** pointer_elts;
    unsigned num_elts;
    unsigned max_elts;
    struct util_pool_t* pool;
};

#define for_each_array_elt

struct util_array_t* util_array_create(struct util_pool_t* pool, unsigned init_max_elts);

int util_array_add_elt(util_array_t* array, const char* buff, int len); 
void util_array_remove(util_array_t* array, unsigned index);

void* util_array_at(const util_array_t* array, unsigned index);

int util_array_zerocopy_add_elt(util_array_t* array, void* elt);
void util_array_zerocopy_remove(util_array_t* array, unsigned index);
#define get_ele_at(type, array, index) (type*)util_array_at(array, index)
#endif//_UTIL_ARRAY_H_

