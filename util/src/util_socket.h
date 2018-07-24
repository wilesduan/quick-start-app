#ifndef WILES_UTIL_SOCK_H
#define WILES_UTIL_SOCK_H

#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define IFI_NAME 16
#define IFI_HADDR 8
#define IFI_ALIAS 1

typedef unsigned char u_char;
typedef unsigned short u_short;


int util_set_socket_and_bind(int fd, const char* addr,unsigned port);

std::string util_get_ip_v4(unsigned long network_ip);
std::string util_get_ip_v4(struct in_addr& network_ip);

std::string util_get_peer_ip_v4(int fd);
int util_get_peer_port(int fd);

int util_connect_2_svr(const char* ip, unsigned port);
int util_connect_2_svr2(const char* ip, unsigned port, int sock_type = SOCK_STREAM);

typedef struct ifi_info_t
{
	char ifi_name[IFI_NAME];
	short ifi_index;
	short ifi_mtu;
	u_char ifi_haddr[IFI_HADDR];
	u_short ifi_hlen;
	short ifi_flags;
	short ifi_myflags;
	struct sockaddr* ifi_addr;
	struct sockaddr* ifi_brdaddr;
	struct sockaddr* ifi_dstaddr;
	struct ifi_info_t* ifi_next;
}ifi_info_t;

ifi_info_t* util_get_ifi_info();
void util_free_ifi_info(ifi_info_t* infi_info);


typedef struct ifip_t
{
	short sa_family;
	char ip[128];
	char ifi_name[IFI_NAME];
	union 
	{
		unsigned long s_addr;
		uint8_t sin6_add6[16];
	}number_u;

	struct ifip_t* next;
}ifip_t;

ifip_t* util_get_local_ifip();
void util_free_ifip(ifip_t** ifip);

#endif//WILES_UTIL_SOCK_H

