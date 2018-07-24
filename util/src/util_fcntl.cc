#include "util_fcntl.h"

#include <fcntl.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

void util_fcntl(int fd)
{
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

	int no_delay = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&no_delay, sizeof(no_delay));

    int flag = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flag|O_NONBLOCK);
}

void util_un_fcntl(int fd)
{
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

	int no_delay = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&no_delay, sizeof(no_delay));

    int flag = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flag & (~O_NONBLOCK));
}
