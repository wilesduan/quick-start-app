#ifndef _WILES_UTIL_BUFF_H
#define _WILES_UTIL_BUFF_H

#include <sys/uio.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#include <list.h>
//#include <util_pools.h>

#include <google/protobuf/message.h>

struct util_buff_t
{
	char* buff;
	int rd_offset;
	int wr_offset;
	list_head chain_list;
};

struct util_buff_chain_t
{
	int block_size;
	struct util_buff_t free_buff;
	struct util_buff_t data_buff;
	//struct util_pool_t* pool;

	int data_len;
};

struct util_buff_chain_t* util_create_buff_chain(int block_size);
void util_reset_buff_chain(struct util_buff_chain_t* chain);
void util_destroy_buff_chain(struct util_buff_chain_t* chain);

int util_get_next_write_buff(struct util_buff_chain_t* chain, struct iovec* iov);

int util_get_rd_buff(struct util_buff_chain_t* chain, size_t len, std::vector<iovec>& iovs);
int util_get_all_rd_buff(struct util_buff_chain_t* chain, std::vector<struct iovec>& iovs);
int util_advance_wr(struct util_buff_chain_t* chain, int len);
int util_advance_rd(struct util_buff_chain_t* chain, int len);
int util_get_rd_buff_len(struct util_buff_chain_t* chain);

int util_write_buff_data(struct util_buff_chain_t* chain, const char* data, int len);

int util_parse_pb_from_buff(::google::protobuf::Message& msg, struct util_buff_chain_t* chain, int len);
int util_serialize_pb_to_buff(const ::google::protobuf::Message& msg, struct util_buff_chain_t* chain);

int util_advacne_iovec(std::vector<iovec>& iovs, int len);
int util_parse_pb_from_iovec(::google::protobuf::Message& msg, std::vector<iovec>& iovs,int len);
int util_serialize_pb_to_iovec(const ::google::protobuf::Message&msg, std::vector<iovec>& iovs);
size_t util_get_iovec_len(std::vector<iovec>& iovs);

#endif//_WILES_UTIL_BUFF_H
