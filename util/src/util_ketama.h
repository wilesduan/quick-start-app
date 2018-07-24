#ifndef __UTIL_KETAMA_HH__
#define __UTIL_KETAMA_HH__

#include <map>
#include <string>
#include <util_md5.h>

uint64_t ketama_hash(unsigned char* digest, int nTime)
{
	uint64_t rv = ((uint64_t) (digest[3 + nTime * 4] & 0xFF) << 24) 
				| ((uint64_t) (digest[2 + nTime * 4] & 0xFF) << 16) 
				| ((uint64_t) (digest[1 + nTime * 4] & 0xFF) << 8)
				| (digest[0 + nTime * 4] & 0xFF);

	return rv & 0xffffffffL; /* Truncate to 32-bits */	
}

uint64_t ketama(const char* room_id, size_t len)
{
	// the virtual node num
	const static int num_vn = 160;

	// Rebuild hash loop map
	std::map<uint64_t, std::string> nodes;
	for(int tb_index = 0; tb_index < 20; ++tb_index)
	{
		for (int vn = 0; vn < num_vn/4; ++vn)
		{
			char tmp[64] = "";
			int tmp_len = snprintf(tmp, 64, "%d%d", tb_index, vn);

			unsigned char md5_name[MD5_DIGEST_LENGTH] = "";	
			md5_sum(tmp, tmp_len, md5_name);

			for (int h = 0; h < 4; ++h)
				nodes.insert(std::make_pair<uint64_t, std::string>(ketama_hash(md5_name, h), std::to_string(tb_index)));
		}
	}

	// Start find table_index of room_id
	unsigned char md5_room[MD5_DIGEST_LENGTH] = "";
	md5_sum(room_id, len, md5_room);
	uint64_t hash_room = ketama_hash(md5_room, 0);
	// LOG_DBG("[tzj] hash_room: %llu", hash_room);

	if (nodes.find(hash_room) == nodes.end())
	{
		auto iter = nodes.upper_bound(hash_room);
		if (iter == nodes.end()) iter = nodes.begin();
		hash_room = iter->first;
	}
	
	// LOG_DBG("[tzj2] hash_room: %llu", hash_room);

	return std::stoull(nodes[hash_room]);
}

#endif
