#ifndef __LIBSRVKIT_NET_H__
#define __LIBSRVKIT_NET_H__

#include <zookeeper.h>
#define K_PROTOCOL_MAX_LEN 20
#define K_IFN_MAX_LEN 20

enum en_accept_strategy
{
	EN_ACCEPT_ROUND_ROBIN = 1,
	EN_ACCEPT_CONNS_LESS_FIRST = 2,
	EN_ACCEPT_REQUEST_LESS_FIRST = 3,
};

typedef struct listen_paramter_t
{
	char ip[128];
	int port;
	char heartbeat;
	String_vector services;
	int acc_num;
	int idle;
	int _public;
	int limit;
	char sz_type[K_PROTOCOL_MAX_LEN+1];
	char sz_ifn[K_IFN_MAX_LEN+1];
	int accept_strategy;
}listen_paramter_t;
#endif//__LIBSRVKIT_NET_H__

