#include <util_cc_hash_map.h>
#include <stdlib.h>

#define K_CC_MAP_CAP 4096
util_cc_hash_map_t* util_create_cc_map()
{
	util_cc_bucket_t* buckets = (util_cc_bucket_t*)calloc(K_CC_MAP_CAP, sizeof(util_cc_bucket_t));
	if(NULL == buckets){
		return NULL;
	}

	util_cc_hash_map_t* map = (util_cc_hash_map_t*)calloc(1, sizeof(util_cc_hash_map_t));
	if(NULL == map){
		return NULL;
	}

	for(size_t i = 0; i < K_CC_MAP_CAP; ++i){
		pthread_mutex_init(&(buckets[i].lock), NULL);
	}

	map->buckets = buckets;
	return map;
}

void util_set_cc_item(util_cc_hash_map_t* map, uint64_t key, void* value, fn_free_value fn)
{
	size_t idx = key&(K_CC_MAP_CAP-1);
	util_cc_bucket_t* bucket = (map->buckets) + idx;
	pthread_mutex_lock(&(bucket->lock));
	struct rb_node** n_rbnode = &(bucket->nodes.rb_node), *parent = NULL;
	while(*n_rbnode){
		util_cc_node_t* node = rb_entry(*n_rbnode, util_cc_node_t, node);
		int result = key - node->key;
		parent = *n_rbnode;
		if(result < 0){
			n_rbnode = &((*n_rbnode)->rb_left);
		}else if(result > 0){
			n_rbnode = &((*n_rbnode)->rb_right);
		}else{
			if(node->fn && node->value){
				(node->fn)(node->value);
			}
			node->value = value;
			pthread_mutex_unlock(&(bucket->lock));
			return;
		}
	}

	util_cc_node_t* node = (util_cc_node_t*)calloc(1, sizeof(util_cc_node_t));
	node->key = key;
	node->value = value;
	node->fn = fn;
	rb_link_node(&(node->node), parent, n_rbnode);
	rb_insert_color(&(node->node), &(bucket->nodes));

	pthread_mutex_unlock(&(bucket->lock));
	return;
}

void* util_acquire_cc_item(util_cc_hash_map_t* map, uint64_t key)
{
	size_t idx = key&(K_CC_MAP_CAP-1);
	util_cc_bucket_t* bucket = (map->buckets) + idx;
	pthread_mutex_lock(&(bucket->lock));

	struct rb_node** n_rbnode = &(bucket->nodes.rb_node);
	while(*n_rbnode){
		util_cc_node_t* node = rb_entry(*n_rbnode, util_cc_node_t, node);
		int result = key - node->key;
		if(result < 0){
			n_rbnode = &((*n_rbnode)->rb_left);
		}else if(result > 0){
			n_rbnode = &((*n_rbnode)->rb_right);
		}else{
			return node->value;
		}
	}

	pthread_mutex_unlock(&(bucket->lock));
	return NULL;
}

void util_release_cc_item(util_cc_hash_map_t* map, uint64_t key)
{
	size_t idx = key&(K_CC_MAP_CAP-1);
	util_cc_bucket_t* bucket = (map->buckets) + idx;
	pthread_mutex_unlock(&(bucket->lock));
}

void util_del_cc_itme(util_cc_hash_map_t* map, uint64_t key)
{
	size_t idx = key&(K_CC_MAP_CAP-1);
	util_cc_bucket_t* bucket = (map->buckets) + idx;
	pthread_mutex_lock(&(bucket->lock));

	struct rb_node** n_rbnode = &(bucket->nodes.rb_node);
	while(*n_rbnode){
		util_cc_node_t* node = rb_entry(*n_rbnode, util_cc_node_t, node);
		int result = key - node->key;
		if(result < 0){
			n_rbnode = &((*n_rbnode)->rb_left);
		}else if(result > 0){
			n_rbnode = &((*n_rbnode)->rb_right);
		}else{
			if(node->fn && node->value){
				(node->fn)(node->value);
			}
			rb_erase(*n_rbnode, &(bucket->nodes));
			free(node);
			break;
		}
	}

	pthread_mutex_unlock(&(bucket->lock));
}
