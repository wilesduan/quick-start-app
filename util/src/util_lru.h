#ifndef __UTIL_LRU_H__
#define __UTIL_LRU_H__

#include <list.h>
#include <time.h>

typedef int(*fn_lru_node_cmp)(const void* k1, size_t k1_len, const void* k2, size_t k2_len);
typedef void (*fn_lru_node_free)(void* node);
typedef void (*fn_lru_node_copy)(const void* src, void* dst);
typedef size_t (*fn_key_hash)(const void* key, size_t key_len);

typedef struct util_lru_options_t
{
	fn_lru_node_cmp cmp;
	fn_lru_node_free free;
	fn_lru_node_copy copy;
	fn_key_hash hash;
	int expire;

	size_t num_slot;
	size_t node_size;
}util_lru_options_t;

typedef struct util_lru_node_t
{
	void* key;
	size_t key_len;

	void* data;
	time_t ts;
	list_head hash_list;
	list_head lru_list;
}util_lru_node_t;

typedef struct util_lru_t
{
	util_lru_options_t options;
	list_head* hash_slots;

	list_head  lru_nodes;
	size_t num_nodes;
}util_lru_t;

util_lru_t* util_malloc_lru(const util_lru_options_t* options);

int util_insert_lru_node(util_lru_t* lru, const void* key, size_t key_len, void* data); 
int util_del_lru_node(util_lru_t* lru, const void* key, size_t key_len);
int util_copy_lru_node_data(util_lru_t* lru, const void* key, size_t key_len, void* data, int* expired);
//util_lru_node_t* util_find_lru_node(util_lru_t* lru, void* key, size_t key_len);
#endif//__UTIL_LRU_H__

