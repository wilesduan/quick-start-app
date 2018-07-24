#ifndef __UTIL_CONCURRENT_HASH_MAP_H_
#define __UTIL_CONCURRENT_HASH_MAP_H_


#include <stdint.h>
#include <pthread.h>
#include <rbtree.h>

typedef void (*fn_free_value)(void* );
typedef struct{
	uint64_t key;
	void* value;
	fn_free_value fn;
	rb_node node;
}util_cc_node_t;
typedef struct{
	pthread_mutex_t lock;
	rb_root nodes;
}util_cc_bucket_t;

typedef struct util_cc_hash_map_t
{
	util_cc_bucket_t* buckets;
}util_cc_hash_map_t;

util_cc_hash_map_t* util_create_cc_map();

void util_set_cc_item(util_cc_hash_map_t* map, uint64_t key, void* value, fn_free_value fn);

void* util_acquire_cc_item(util_cc_hash_map_t* map, uint64_t key);
void util_release_cc_item(util_cc_hash_map_t* map, uint64_t key);

void util_del_cc_itme(util_cc_hash_map_t* map, uint64_t key);
#endif//__UTIL_CONCURRENT_HASH_MAP_H_
