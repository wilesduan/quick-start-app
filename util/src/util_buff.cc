#include "util_buff.h"
#include <strings.h>
#include <errno.h>
#include <assert.h>

#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/message_lite.h>
#include "concatenating_output_stream.h"

struct util_buff_chain_t* util_create_buff_chain(int block_size)
{
	if(0 == block_size)
	{
		return NULL;
	}

	struct util_buff_chain_t* chain = (util_buff_chain_t*)calloc(1, sizeof(util_buff_chain_t));
	if(NULL == chain)
	{
		return NULL;
	}

	chain->block_size = block_size;
	chain->data_len = 0;

	INIT_LIST_HEAD(&(chain->free_buff.chain_list));
	INIT_LIST_HEAD(&(chain->data_buff.chain_list));

	//chain->pool = pool;

	return chain;
}

void util_reset_buff_chain(struct util_buff_chain_t* chain)
{
	if(NULL == chain){
		return;
	}

	list_head* p = NULL;
	list_head* next = NULL;
	list_for_each_safe(p, next, &(chain->data_buff.chain_list)){
		util_buff_t* bf = list_entry(p, util_buff_t, chain_list);
		list_del(p);
		INIT_LIST_HEAD(p);
		bf->rd_offset = bf->wr_offset = 0;
		list_add_tail(p, &(chain->free_buff.chain_list));
	}

	int keep = 1;
	p = next = NULL;
	list_for_each_safe(p, next, &(chain->free_buff.chain_list)){
		if(keep){
			keep = 0;
			continue;
		}


		util_buff_t* bf = list_entry(p, util_buff_t, chain_list);
		list_del(p);
		free(bf->buff);
		free(bf);
	}

	chain->data_len = 0;
}

static void util_destroy_buff(util_buff_t* buffs)
{
	if(NULL == buffs){
		return;
	}

	list_head* p = NULL;
	list_head* next = NULL;
	list_for_each_safe(p, next, &(buffs->chain_list)){
		util_buff_t* bf = list_entry(p, util_buff_t, chain_list);
		list_del(p);
		free(bf->buff);
		free(bf);
		//util_pfree(pool, bf->buff);
		//util_pfree(pool, bf);
	}
}

void util_destroy_buff_chain(struct util_buff_chain_t* chain)
{
	if(NULL == chain)
	{
		return;
	}

	util_destroy_buff(&chain->free_buff);
	util_destroy_buff(&chain->data_buff);

	free(chain);
	//util_pfree(chain->pool, chain);
}

static struct util_buff_t* get_buff_from_free_list(struct util_buff_chain_t* chain)
{
	if(list_empty(&(chain->free_buff.chain_list)))
	{
		char* char_buff = (char*)calloc(1, chain->block_size);
		if(NULL == char_buff)
		{
			return NULL;
		}

		struct util_buff_t* buff = (struct util_buff_t*)calloc(1, sizeof(struct util_buff_t));
		if(NULL == buff)
		{
			free(char_buff);
			return NULL;
		}

		buff->buff = char_buff;
		INIT_LIST_HEAD(&(buff->chain_list));
		return buff;
	}

	list_head* buff_head = chain->free_buff.chain_list.next;
	list_del(buff_head);

	struct util_buff_t* buff = list_entry(buff_head, util_buff_t, chain_list);
	buff->rd_offset = buff->wr_offset = 0;
	return buff;
}

static int get_new_write_buff(struct util_buff_chain_t* chain, struct iovec* iov)
{
	util_buff_t* free_buff = get_buff_from_free_list(chain);
	if(NULL == free_buff)
	{
		return -1;
	}

	list_add_tail(&(free_buff->chain_list), &(chain->data_buff.chain_list));

	iov->iov_base = free_buff->buff;
	iov->iov_len = chain->block_size;

	return 0;
}

int util_get_next_write_buff(struct util_buff_chain_t* chain, struct iovec* iov)
{
	if(NULL == chain || NULL == iov)
	{
		return -1;
	}

	if(list_empty(&(chain->data_buff.chain_list)))
	{
		return get_new_write_buff(chain, iov);
	}

	list_head* tail = chain->data_buff.chain_list.prev;
	struct util_buff_t* buff = list_entry(tail, util_buff_t, chain_list);

	if(buff->wr_offset >= chain->block_size)
	{
		return get_new_write_buff(chain, iov);
	}

	iov->iov_base = buff->buff + buff->wr_offset;
	iov->iov_len = chain->block_size - buff->wr_offset;

	return 0;
}

int util_get_rd_buff(struct util_buff_chain_t* chain, size_t need_len, std::vector<iovec>& iovs)
{
	if(NULL == chain)
	{
		return -1;
	}

	iovs.reserve(10);
	size_t total_len = 0;

	list_head* buff;
	list_for_each(buff, &(chain->data_buff.chain_list))
	{
		util_buff_t* util_buff = list_entry(buff, util_buff_t, chain_list);
		int len = util_buff->wr_offset - util_buff->rd_offset;
		if(len > 0)
		{
			struct iovec io;
			iovs.push_back(io);
			struct iovec& iov = iovs.back();
			int remain_len = need_len - total_len;

			iov.iov_base = util_buff->buff + util_buff->rd_offset;
			iov.iov_len = len > remain_len?remain_len:len;
			total_len += iov.iov_len;
		}

		if(total_len >= need_len)
		{
			break;
		}
	}

	if(total_len != need_len)
	{
		iovs.clear();
		return -2;
	}

	return 0;
}
int util_get_all_rd_buff(struct util_buff_chain_t* chain, std::vector<struct iovec>& iovs)
{
	if(NULL == chain)
	{
		return -1;
	}

	iovs.reserve(10);

	list_head* buff;
	list_for_each(buff, &(chain->data_buff.chain_list))
	{
		util_buff_t* util_buff = list_entry(buff, util_buff_t, chain_list);
		int len = util_buff->wr_offset - util_buff->rd_offset;
		if(len > 0)
		{
			struct iovec io;
			iovs.push_back(io);
			struct iovec& iov = iovs.back();
			iov.iov_base = util_buff->buff + util_buff->rd_offset;
			iov.iov_len = len;
		}
	}

	return 0;
}

int util_advance_wr(struct util_buff_chain_t* chain, int len)
{
	if(NULL == chain || list_empty(&(chain->data_buff.chain_list)))
	{
		return -1;
	}

	list_head* tail = chain->data_buff.chain_list.prev;
	struct util_buff_t* util_buff = list_entry(tail, util_buff_t, chain_list);
	if(util_buff->wr_offset + len > chain->block_size)
	{
		return -2;
	}

	chain->data_len += len;

	util_buff->wr_offset += len;
	return 0;
}

int util_advance_rd(struct util_buff_chain_t* chain, int len)
{
	if(NULL == chain || list_empty(&(chain->data_buff.chain_list)))
	{
		return -1;
	}

	int advance_len = 0;

	list_head* rd_buff;
	std::vector<list_head*> del_nodes;
	list_for_each(rd_buff, &(chain->data_buff.chain_list))
	{
		if(advance_len >= len)
		{
			break;
		}
		struct util_buff_t* util_buff = list_entry(rd_buff, util_buff_t, chain_list);
		int rest_len = util_buff->wr_offset - util_buff->rd_offset;
		if(rest_len <= len - advance_len)
		{
			util_buff->rd_offset += rest_len;
			if(util_buff->rd_offset >= chain->block_size)
			{
				del_nodes.push_back(rd_buff);
			}

			advance_len += rest_len;
		}
		else
		{
			util_buff->rd_offset += (len - advance_len);
			advance_len = len;
			break;
		}
	}

	for(unsigned i = 0; i < del_nodes.size(); ++i)
	{
		list_head* node = del_nodes[i];
		list_del(node);
		struct util_buff_t* buff = list_entry(node, util_buff_t, chain_list);
		buff->rd_offset = buff->wr_offset = 0;
		list_add_tail(node, &(chain->free_buff.chain_list));
	}

	chain->data_len -= advance_len;
	assert(chain->data_len >= 0);
	return advance_len;
}

int util_write_buff_data(struct util_buff_chain_t* chain, const char* data, int len)
{
	if(NULL == chain)
	{
		return -1;
	}

	if(NULL == data || 0 == len)
	{
		return 0;
	}

	struct iovec iov;
	int wr_len = 0;
	while(wr_len < len)
	{
		int rc  = util_get_next_write_buff(chain, &iov);
		if(rc)
		{
			return wr_len;
		}

		int cp_len = len - wr_len> (int)(iov.iov_len)? iov.iov_len:(len - wr_len);

		memcpy(iov.iov_base, data+wr_len, cp_len);
		wr_len += cp_len;
		util_advance_wr(chain, cp_len);
	}

	return wr_len;
}

int util_parse_pb_from_buff(::google::protobuf::Message& msg, struct util_buff_chain_t* chain, int len)
{
	if(NULL == chain)
	{
		return -1;
	}

	std::vector<struct iovec> iovs;
	int rc = util_get_all_rd_buff(chain, iovs);
	if(rc){
		return rc;
	}

	if(iovs.size() == 0){
		return 0;
	}

	google::protobuf::io::ZeroCopyInputStream** streams = (::google::protobuf::io::ZeroCopyInputStream**)calloc(iovs.size(), sizeof(::google::protobuf::io::ZeroCopyInputStream*));
	if(NULL == streams){
		return -2;
	}

	bool parse;
	int total_buff_len = 0;
	for(unsigned i = 0; i < iovs.size(); ++i)
	{
		total_buff_len += iovs[i].iov_len;
		int parse_len = total_buff_len < len?iovs[i].iov_len:(iovs[i].iov_len-(total_buff_len-len));
		streams[i] = new ::google::protobuf::io::ArrayInputStream(iovs[i].iov_base, parse_len);
		if(NULL == streams[i]){
			rc = -3;
			break;
		}
	}
	::google::protobuf::io::ConcatenatingInputStream stream(streams, iovs.size());

	if(rc){
		goto free;
	}

	if(total_buff_len < len)
	{
		rc = 1;
		goto free;
	}

	parse = msg.ParseFromZeroCopyStream(&stream);
	if(!parse)
	{
		rc = -1;
		goto free;
	}

free:
	for(unsigned i = 0; i < iovs.size(); ++i)
	{
		if(streams[i] != NULL)
		{
		    delete streams[i];
	    	streams[i] = NULL;
		}
	}

	free(streams);

	return rc;
}

int util_get_rd_buff_len(struct util_buff_chain_t* chain)
{
	if(NULL == chain)
	{
		return 0;
	}

	return chain->data_len;
}

int util_serialize_pb_to_buff(const ::google::protobuf::Message& msg, struct util_buff_chain_t* chain)
{
	struct iovec iov;
	int rc = util_get_next_write_buff(chain, &iov);
	if(rc)
	{
		return rc;
	}

	int len_buff = iov.iov_len;
	rc = 0;

	google::protobuf::io::ZeroCopyOutputStream** streams = NULL;
	unsigned num_stream = 0;

	std::vector<struct util_buff_t*> vbuffs;
	unsigned i = 0;
    struct util_buff_t* buff;
	bool serialize;
	::google::protobuf::io::ConcatenatingOutputStream outstream(streams, 0);
	while(len_buff < msg.ByteSize())
	{
		buff = get_buff_from_free_list(chain);
		if(NULL == buff)
		{
			rc = -1;
			goto end_serialize;
		}

		len_buff += chain->block_size;
		vbuffs.push_back(buff);
	}

	streams = (::google::protobuf::io::ZeroCopyOutputStream**)calloc(1+vbuffs.size(), sizeof(::google::protobuf::io::ZeroCopyOutputStream*));
	if(NULL == streams){
		rc = -2;
		goto end_serialize;
	}
	num_stream = 1+vbuffs.size();

	streams[0] = new ::google::protobuf::io::ArrayOutputStream(iov.iov_base, iov.iov_len);
	for(i = 0; i < vbuffs.size(); ++i)
	{
		streams[i+1] = new ::google::protobuf::io::ArrayOutputStream(vbuffs[i]->buff, chain->block_size);
	}

	outstream.Reset(streams, 1+vbuffs.size());
	serialize = msg.SerializeToZeroCopyStream(&outstream);
	if(!serialize)
	{
		rc = -3;
		goto end_serialize;
	}

	if(0 == vbuffs.size())
	{
		util_advance_wr(chain, msg.ByteSize());
	}
	else
	{
		util_advance_wr(chain, iov.iov_len);
		len_buff = msg.ByteSize() - iov.iov_len;
		for(i = 0; i < vbuffs.size(); ++i)
		{
			util_buff_t* buff = vbuffs[i];
			list_add_tail(&(buff->chain_list), &(chain->data_buff.chain_list));
			buff->wr_offset = len_buff >= chain->block_size?chain->block_size:len_buff;
			len_buff -= buff->wr_offset;
			chain->data_len += buff->wr_offset;
		}
		vbuffs.clear();
	}

end_serialize:
	for(i = 0; i < vbuffs.size(); ++i)
	{
		util_buff_t* buff = vbuffs[i];
		list_add_tail(&(buff->chain_list), &(chain->free_buff.chain_list));
	}

	for(i = 0; i < num_stream; ++i)
	{
		if(streams[i] != NULL)
		{
			delete streams[i];
			streams[i] = NULL;
		}
	}

	if(streams){
		free(streams);
	}

	return rc;
}

int util_parse_pb_from_iovec(::google::protobuf::Message& msg, std::vector<iovec>& iovs, int len)
{
	int num_ivec = iovs.size(); 
	if(len <= 0 || num_ivec <= 0)
	{
		return -1;
	}

	int total_len = 0;
	for(int i = 0; i < num_ivec; ++i)
	{
		total_len += iovs[i].iov_len;
	}

	if(len > total_len)
	{
		return -2;
	}

	::google::protobuf::io::ZeroCopyInputStream** streams = (::google::protobuf::io::ZeroCopyInputStream**)calloc(num_ivec, sizeof(::google::protobuf::io::ZeroCopyInputStream*));
	if(NULL == streams)
	{
		return -3;
	}

	int  total_parse_len = 0;
	int i = 0;
	for(; i < num_ivec && total_parse_len<len; ++i)
	{
		int parse_len = (int)iovs[i].iov_len+total_parse_len>len?len-total_parse_len:iovs[i].iov_len;
		streams[i] = new ::google::protobuf::io::ArrayInputStream(iovs[i].iov_base, parse_len);
		total_parse_len += parse_len;
	}

	::google::protobuf::io::ConcatenatingInputStream stream(streams, i);
	int rc = 0;
	bool parse = msg.ParseFromZeroCopyStream(&stream);
	if(!parse)
	{
		rc = -4;
	}

	for(i = 0; i < num_ivec; ++i)
	{
		if(streams[i])
		{
			delete streams[i];
			streams[i] = NULL;
		}
	}

	free(streams);
	return rc;
}

int util_serialize_pb_to_iovec(const ::google::protobuf::Message&msg, std::vector<iovec>& iovs)
{
	int num_iovec = iovs.size();
	int total_len = 0;
	int i = 0;
	for(; i < num_iovec; ++i)
	{
		total_len += iovs[i].iov_len;
		if(total_len > msg.ByteSize())
		{
			iovs[i].iov_len -= (total_len - msg.ByteSize());
			break;
		}
	}

	for(i = i+1; i <num_iovec; ++i)
	{
		iovs[i].iov_len = 0;
	}

	if(total_len < msg.ByteSize())
	{
		return -1;
	}

	::google::protobuf::io::ZeroCopyOutputStream** streams = (::google::protobuf::io::ZeroCopyOutputStream**)calloc(num_iovec, sizeof(::google::protobuf::io::ZeroCopyOutputStream*));
	if(NULL == streams)
	{
		return -2;
	}

	for(i = 0; i < num_iovec; ++i)
	{
		streams[i] = new ::google::protobuf::io::ArrayOutputStream(iovs[i].iov_base, iovs[i].iov_len);
	}

	::google::protobuf::io::ConcatenatingOutputStream outstream(streams, num_iovec);
	int rc = 0;
	bool serialize = msg.SerializeToZeroCopyStream(&outstream);
	if(!serialize)
	{
		rc = -3;
	}

	for(i = 0; i < num_iovec; ++i)
	{
		delete streams[i];
		streams[i] = NULL;
	}

	free(streams);
	return rc;
}

int util_advacne_iovec(std::vector<iovec>& iovs, int len)
{
	int iovec_len = util_get_iovec_len(iovs);
	if(iovec_len < len){
		return -1;
	}

	size_t i = 0;
	size_t offset = 0;
	size_t total_offset = 0; 
	for(i = 0; i < iovs.size(); ++i)
	{
		size_t size = iovs[i].iov_len;
		if(total_offset + size < (size_t)len)
		{
			total_offset += size;
			continue;
		}

		offset = len - total_offset;
		iovs[i].iov_base = (char*)(iovs[i].iov_base) + offset;
		iovs[i].iov_len -= offset;
		if(iovs[i].iov_len == 0){
			++i;
		}

		break;
	}

	if(i == 0)
	{
		return 0;
	}

	std::vector<iovec>::iterator first = iovs.begin();
	std::vector<iovec>::iterator last = iovs.begin() + i;

	iovs.erase(first, last);
	return 0;
}

size_t util_get_iovec_len(std::vector<iovec>& iovs)
{
	size_t len = 0;
	for(size_t i = 0; i < iovs.size(); ++i)
	{
		len += iovs[i].iov_len;
	}
	
	return len;
}

