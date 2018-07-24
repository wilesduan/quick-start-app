#include "util_socket.h"
#include <sys/ioctl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>


#include "util_fcntl.h"

int util_set_socket_and_bind(int fd, const char* addr, unsigned port)
{
    util_fcntl(fd);
    sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
	if(NULL == addr){
		inet_pton(AF_INET, "0.0.0.0", &bind_addr.sin_addr);
	}else{
		if(inet_pton(AF_INET, addr, &bind_addr.sin_addr) != 1){
			inet_pton(AF_INET, "0.0.0.0", &bind_addr.sin_addr);
		}
	}

    return bind(fd, (sockaddr*)&bind_addr, sizeof(bind_addr));
}

std::string util_get_ip_v4(unsigned long network_ip)
{
    char sz_ip[16] = {0};
    inet_ntop(AF_INET, &network_ip, sz_ip, sizeof(sz_ip));
    return sz_ip;
}

std::string util_get_ip_v4(struct in_addr& network_ip)
{
    return util_get_ip_v4(network_ip.s_addr);
}

std::string util_get_peer_ip_v4(int fd)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    getpeername(fd, (sockaddr*)&addr, &len);
    return util_get_ip_v4(addr.sin_addr);
}

int util_get_peer_port(int fd)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    getpeername(fd, (sockaddr*)&addr, &len);
	return ntohs(addr.sin_port);
}

int util_connect_2_svr2(const char* ip, unsigned port, int sock_type)
{
	int sock = socket(AF_INET, sock_type, 0);
	if(sock <= 0){
		return -1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	int rc = inet_pton(AF_INET, ip, &(addr.sin_addr));
	if(rc <= 0)
	{
		close(sock);
		return -2;
	}

	util_fcntl(sock);
	rc = connect(sock, (sockaddr*)&addr, sizeof(sockaddr_in));
	if(rc){
		if(errno != EINPROGRESS){
			close(sock);
			return -3;
		}
		struct pollfd   wfd[1];
		wfd[0].fd = sock;
		wfd[0].events = POLLOUT;
		long msec = 50;

		rc = poll(wfd, 1, msec);
		if(rc <= -1){
			close(sock);
			return -3;
		}

		int opt = 0;
		socklen_t len = sizeof(opt);
		getsockopt(sock, SOL_SOCKET, SO_ERROR, &opt, &len);
		if(opt){
			errno = opt;
			close(sock);
			return -4;
		}
	}

	return sock;
}

int util_connect_2_svr(const char* ip, unsigned port)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock <= 0)
	{
		return -1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	int rc = inet_pton(AF_INET, ip, &(addr.sin_addr));
	if(rc <= 0)
	{
		close(sock);
		return -2;
	}

	//util_fcntl(sock);

	rc = connect(sock, (sockaddr*)&addr, sizeof(sockaddr_in));
	if(rc){
		close(sock);
		return -3;
		/*
		if(errno != EINPROGRESS){
			close(sock);
			return -3;
		}

		fd_set r_set;
		fd_set w_set;
		FD_ZERO(&r_set);
		FD_ZERO(&w_set);
		FD_SET(sock, &r_set);
		FD_SET(sock, &w_set);

		struct timeval tv={1, 0};
		rc = select(sock+1, &r_set, &w_set, NULL, &tv);
		if(rc <= 0){
			close(sock);
			return -3;
		}else{ 
			int opt = 0;
			socklen_t len = sizeof(opt);
			getsockopt(sock, SOL_SOCKET, SO_ERROR, &opt, &len);
			if(opt){
				printf("so_error:%d\n", opt);
				close(sock);
				return -4;
			}
		}
		*/
	}

	util_fcntl(sock);
	return sock;
}

ifi_info_t* util_get_ifi_info()
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0)
	{
		return NULL;
	}

	struct ifconf ifc;
	char* buf = NULL;
	int lastlen = 0;
	int len = 100*sizeof(struct ifreq);
	for(;;)
	{
		buf = (char*)calloc(1, len);
		if(NULL == buf)
		{
			close(sockfd);
			return NULL;
		}

		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		if(ioctl(sockfd, SIOCGIFCONF, &ifc) < 0)
		{
			if(errno != EINVAL || lastlen != 0)
			{
				printf("ioctl error");
			}
		}
		else
		{
			if(ifc.ifc_len == lastlen)
			{
				break;
			}
			lastlen = ifc.ifc_len;
		}

		len += 10*sizeof(struct ifreq);
		free(buf);
	}

	ifi_info_t* ifihead = NULL;
	ifi_info_t** ifipnext = &ifihead;
	char lastname[IFNAMSIZ] = {0};
	char* sdlname = NULL;
	int idx = 0;
	char* haddr = NULL;
	int hlen = 0;

	for(char* ptr = buf; ptr < buf + ifc.ifc_len;)
	{
		struct ifreq* ifr = (struct ifreq*)ptr;

#ifdef HAVE_SOCKADDR_SA_LEN
		len = sizeof(struct sockaddr) > ifr->ifr_addr.sa_len?sizeof(struct sockaddr):ifr->ifr_addr.sa_len;
#else
		switch(ifr->ifr_addr.sa_family)
		{
#ifdef IPV6
			case AF_INET6:
				len = sizeof(struct sockaddr_in6);
				break;
#endif
			case AF_INET:
			default:
				len = sizeof(struct sockaddr);
				break;
		}
#endif//HAVE_SOCKADDR_SA_LEN
		//ptr += sizeof(ifr->ifr_name) + len;
		ptr += sizeof(struct ifreq);

#ifdef HAVE_SOCKADDR_DL_STRUCT
		if(ifr->ifr_addr.sa_family == AF_LINK)
		{
			struct sockaddr_dl* sdl = (struct sockaddr_dl*)&ifr->ifr_addr;
			sdlname = ifr->ifr_name;
			idx = sdl->sdl_index;
			haddr = sdl->sdl_data + sdl->sdl_nlen;
			hlen = sdl->sdl_alen;

		}
#endif//HAVE_SOCKADDR_DL_STRUCT

		int myflags = 0;
		char* cptr = NULL;
		if((cptr = strchr(ifr->ifr_name, ':')) != NULL)
		{
			*cptr = 0;
		}
		if(strncmp(lastname, ifr->ifr_name, IFNAMSIZ) == 0)
		{
			myflags = IFI_ALIAS;
		}
		memcpy(lastname, ifr->ifr_name, IFNAMSIZ);
		struct ifreq ifrcopy = *ifr;
		if(ioctl(sockfd, SIOCGIFFLAGS, &ifrcopy) < 0)
		{
			continue;
		}

		int flags = ifrcopy.ifr_flags;
		if((flags & IFF_UP) == 0)
		{
			continue;
		}

		ifi_info_t* ifi = (ifi_info_t*)calloc(1, sizeof(ifi_info_t));
		if(NULL == ifi)
		{
			continue;
		}

		*ifipnext = ifi;
		ifipnext = &ifi->ifi_next;

		ifi->ifi_flags = flags;
		ifi->ifi_myflags = myflags;
		ifi->ifi_mtu = 0;
#if defined(SIOCGIFMTU) && defined(HAVE_STRUCT_IFREQ_IFR_MTU)
		if(ioctl(sockfd, SIOCGIFMTU, &ifrcopy) >= 0)
		{
			ifi->ifi_mtu = ifrcopy.ifr_mtu;
		}
#else
		ifi->ifi_mtu = 0;
#endif

		memcpy(ifi->ifi_name, ifr->ifr_name, IFI_NAME);
		ifi->ifi_name[IFI_NAME-1] = 0;
		if(sdlname == NULL || strcmp(sdlname, ifr->ifr_name) != 0)
		{
			idx = hlen = 0;
		}
		
		ifi->ifi_index = idx;
		ifi->ifi_hlen = hlen;
		if(ifi->ifi_hlen > IFI_HADDR)
		{
			ifi->ifi_hlen = IFI_HADDR;
		}

		if(hlen)
		{
			memcpy(ifi->ifi_haddr, haddr, ifi->ifi_hlen);
		}

		struct sockaddr_in* sinptr;
		struct sockaddr_in6* sin6ptr;
		switch(ifr->ifr_addr.sa_family)
		{
			case AF_INET:
				sinptr = (struct sockaddr_in*)&ifr->ifr_addr;
				ifi->ifi_addr = (struct sockaddr*)calloc(1, sizeof(struct sockaddr_in));
				if(ifi->ifi_addr)
				{
					memcpy(ifi->ifi_addr, sinptr, sizeof(struct sockaddr_in));
				}
#ifdef SIOCGIFBRDADDR
				if((flags & IFF_BROADCAST) && ioctl(sockfd, SIOCGIFBRDADDR, &ifrcopy) >= 0)
				{
					sinptr = (struct sockaddr_in*) &ifrcopy.ifr_broadaddr;
					ifi->ifi_brdaddr = (sockaddr*)calloc(1, sizeof(struct sockaddr_in));
					if(ifi->ifi_brdaddr)
					{
						memcpy(ifi->ifi_brdaddr, sinptr,sizeof(struct sockaddr_in));
					}
				}
#endif

#ifdef SIOCGIFDSTADDR
				if((flags & IFF_POINTOPOINT) && ioctl(sockfd, SIOCGIFDSTADDR, &ifrcopy) >= 0)
				{
					sinptr = (struct sockaddr_in*)&ifrcopy.ifr_dstaddr;
					ifi->ifi_dstaddr = (sockaddr*)calloc(1, sizeof(struct sockaddr_in));
					if(ifi->ifi_dstaddr)
					{
						memcpy(ifi->ifi_dstaddr, sinptr, sizeof(struct sockaddr_in));
					}
				}
#endif
				break;

			case AF_INET6:
				sin6ptr = (struct sockaddr_in6*)&ifr->ifr_addr;
				ifi->ifi_addr = (sockaddr*)calloc(1, sizeof(struct sockaddr_in6));
				if(ifi->ifi_addr)
				{
					memcpy(ifi->ifi_addr, sin6ptr, sizeof(struct sockaddr_in6));
				}

#ifdef SIOCGIFDSTADDR
				if((flags & IFF_POINTOPOINT) && ioctl(sockfd, SIOCGIFDSTADDR, &ifrcopy))
				{
					sin6ptr = (struct sockaddr_in6*)&ifrcopy.ifr_dstaddr;
					ifi->ifi_dstaddr = (struct sockaddr*)calloc(1, sizeof(struct sockaddr_in6));
					if(ifi->ifi_dstaddr)
					{
						memcpy(ifi->ifi_dstaddr, sin6ptr, sizeof(struct sockaddr_in6));
					}
				}
#endif
				break;
			default:
				break;

		}
	}

	close(sockfd);
	free(buf);
	return ifihead;
}

void util_free_ifi_info(ifi_info_t* ifihead)
{
	struct ifi_info_t* ifi, *ifinext;
	for(ifi = ifihead; ifi != NULL; ifi = ifinext)
	{
		if(ifi->ifi_addr)
		{
			free(ifi->ifi_addr);
			ifi->ifi_addr = NULL;
		}
		if(ifi->ifi_brdaddr)
		{
			free(ifi->ifi_brdaddr);
			ifi->ifi_brdaddr = NULL;
		}
		if(ifi->ifi_dstaddr)
		{
			free(ifi->ifi_dstaddr);
			ifi->ifi_dstaddr = NULL;
		}

		ifinext = ifi->ifi_next;
		free(ifi);
	}
}

ifip_t* util_get_local_ifip()
{
	ifip_t *ifiphead = NULL;
	ifip_t **ifip_next;
	ifiphead = NULL;
	ifi_info_t* ifi_infos = util_get_ifi_info();
	if(NULL == ifi_infos)
	{
		return NULL;
	}

	ifip_next = &ifiphead;
	ifi_info_t *ifi, *ifi_next;
	for(ifi = ifi_infos; ifi != NULL;ifi = ifi_next)
	{
		ifi_next = ifi->ifi_next;
		ifip_t* ifip = (ifip_t*)calloc(1, sizeof(ifip_t));
		if(NULL == ifip)
		{
			continue;
		}

		ifip->sa_family = ifi->ifi_addr->sa_family;
		switch(ifip->sa_family)
		{
#ifdef IPV6
			case AF_INET6:
				inet_ntop(AF_INET6,((sockaddr_in6*)(ifi->ifi_addr))->sin6_addr, ifip->ip, sizeof(ifip->ip));
				memcpy(ifip->number_u.sin6_addr, ((sockaddr_in6*)(ifi->ifi_addr))->sin6_addr, sizeof(ifip->number_u.sin6_addr));
				break;
#endif
			case AF_INET:
			default:
				inet_ntop(AF_INET,&((sockaddr_in*)(ifi->ifi_addr))->sin_addr, ifip->ip, sizeof(ifip->ip));
				ifip->number_u.s_addr = ((sockaddr_in*)(ifi->ifi_addr))->sin_addr.s_addr;
				break;
		}

		strcpy(ifip->ifi_name, ifi->ifi_name);

		*ifip_next = ifip;
		ifip_next = &ifip->next;
	}

	util_free_ifi_info(ifi_infos);

	return ifiphead;
}

void util_free_ifip(ifip_t** pifiphead)
{
	if(NULL == pifiphead)
	{
		return;
	}

	ifip_t* ifiphead = *pifiphead;
	if(NULL == ifiphead)
	{
		return;
	}

	ifip_t *ifipnext, *ifip;
	for(ifip = ifiphead; ifip != NULL; ifip = ifipnext)
	{
		ifipnext = ifip->next;
		free(ifip);
	}

	*pifiphead = NULL;
}

