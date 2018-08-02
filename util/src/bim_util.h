#ifndef __BLINK_UTIL_H__
#define __BLINK_UTIL_H__
#include <list.h>
#include <murmur3_hash.h>
#include <time_util.h>
#include <util_array.h>
#include <util_fcntl.h>
#include <util_log.h>
#include <util_md5.h>
#include <util_mem_cache.h>
#include <util_mem_pool.h>
#include <util_pools.h>
#include <util_socket.h>
#include <util_buff.h>
#include <util_json2pb.h>
#include <util_cc_hash_map.h>
#include <util_cipher.h>
#include <rbtree.h>
#include <util_base64.h>
#include <util_aes.h>
#include <util_file.h>
#include <util_lancer.h>
#include <util_http_invoke.h>
#include <sched_cpu_affinity.h>
#include <util_circuit_breaker.h>



#define BEGIN_CALC_RPC_COST() \
        {struct timeval macro_start_val; \
		  gettimeofday(&macro_start_val, NULL);

#define END_CALC_RPC_COST(servicename, method, traceid) \
		struct timeval macro_end_val;\
		gettimeofday(&macro_end_val, NULL);\
		int milli_cost = 1000*(macro_end_val.tv_sec-macro_start_val.tv_sec) +(macro_end_val.tv_usec-macro_start_val.tv_usec)/1000;\
		LOG_INFO("call %s:%s, trace_id:%s, cost:%llu ms", servicename, method,traceid, milli_cost); \
		add_trace_point(ctx, servicename, method, __FILE__, milli_cost);\
		}


#define VA_COUNT_EX_EX(first, ...) first
#define VA_COUNT_EX(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, ...) VA_COUNT_EX_EX(__VA_ARGS__)
#define VA_COUNT_PARAM(...) VA_COUNT_EX(__VA_ARGS__, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)

#endif//__BLINK_UTIL_H__
