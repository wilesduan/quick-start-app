#include <util_lru.h>
#include <stdlib.h>
#include <string.h>

util_lru_t* util_malloc_lru(const util_lru_options_t* options)
{
	if(!options){
		return NULL;
	}

	util_lru_t* lru = (util_lru_t*)calloc(1, sizeof(util_lru_t));
	if(!lru){
		return NULL;
	}

	memcpy(&(lru->options), options, sizeof(util_lru_options_t));
	lru->hash_slots = (list_head*)calloc(options->num_slot, sizeof(list_head));
	for(size_t i = 0; i < options->num_slot; ++i){
		INIT_LIST_HEAD(lru->hash_slots+i);
	}

	INIT_LIST_HEAD(&(lru->lru_nodes));
	return lru;
}

static util_lru_node_t* new_or_expire_lru_node(util_lru_t* lru, const void* key, size_t key_len)
{
	util_lru_node_t* node = NULL;
	if(lru->num_nodes >= lru->options.node_size){
		list_head* p = pop_list_node(&(lru->lru_nodes));
		node = list_entry(p, util_lru_node_t, lru_list);
		list_del_init(&(node->hash_list));
	}else{
		node = (util_lru_node_t*)calloc(1, sizeof(util_lru_node_t));
		++lru->num_nodes;
		INIT_LIST_HEAD(&node->hash_list);
		INIT_LIST_HEAD(&node->lru_list);
	}

	return node;
}

static util_lru_node_t* util_find_lru_node(util_lru_t* lru, const void* key, size_t key_len)
{
	size_t hash = (lru->options.hash)(key, key_len);
	size_t idx = hash%(lru->options.num_slot);
	list_head* head = lru->hash_slots + idx;
	list_head* p = NULL;
	list_for_each(p, head){
		util_lru_node_t* node = list_entry(p, util_lru_node_t, hash_list);
		if((lru->options.cmp)(key, key_len, node->key, node->key_len) == 0){
			return node;
		}
	}

	return NULL;
}

int util_insert_lru_node(util_lru_t* lru, const void* key, size_t key_len, void* data)
{
	if(!lru || !key || !key_len || !data){
		return 0;
	}

	util_lru_node_t* node = util_find_lru_node(lru, key, key_len);
	if(node){
		if(node->data != data){
			(lru->options.free)(node->data);
			node->data = data;
		}

		time(&(node->ts));
		return 0;
	}

	node = new_or_expire_lru_node(lru, key, key_len);
	if(node->key){
		free(node->key);
	}
	node->key = calloc(1, key_len);
	node->key_len = key_len;
	memcpy(node->key, key, key_len);

	if(node->data){
		(lru->options.free)(node->data);
	}
	node->data = data;
	time(&(node->ts));

	list_add_tail(&(node->lru_list), &(lru->lru_nodes));

	size_t hash = (lru->options.hash)(key, key_len);
	size_t idx = hash%(lru->options.num_slot);
	list_head* p = lru->hash_slots + idx;
	list_add(&(node->hash_list), p);
	return 0;
}

int util_del_lru_node(util_lru_t* lru, const void* key, size_t key_len)
{
	if(!lru || !key || !key_len){
		return 0;
	}

	util_lru_node_t* node = util_find_lru_node(lru, key, key_len);
	if(!node){
		return 0;
	}

	list_del(&node->hash_list);
	list_del(&node->lru_list);
	list_add(&node->lru_list, &lru->lru_nodes);
	return 0;
}

int util_copy_lru_node_data(util_lru_t* lru, const void* key, size_t key_len, void* data, int* expired)
{
	if(!lru || !key || !key_len){
		return 0;
	}

	util_lru_node_t* node = util_find_lru_node(lru, key, key_len);
	if(!node){
		return -1;
	}

	if(expired){
		*expired = 0;
	}

	time_t now;
	time(&now);
	if(now >= node->ts + lru->options.expire){
		if(expired) *expired = 1;
	}else{
		//update lru order
		list_del(&node->lru_list);
		list_add_tail(&node->lru_list, &lru->lru_nodes);
		//node->ts = now;
	}

	(lru->options.copy)(node->data, data);
	return 0;
}
