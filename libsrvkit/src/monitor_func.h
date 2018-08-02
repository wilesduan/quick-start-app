#ifndef __LIBSRVKIT_MONITOR_FUNC_H__
#define __LIBSRVKIT_MONITOR_FUNC_H__
#include <string>
#include <map>
#include <sys/types.h>
#include <sys/socket.h>

int fn_update_monitor_info(int udp_fd, const struct sockaddr *dest_addr, socklen_t addrlen, const char* service, const std::map<std::string, int>& monitor_infos);
#endif//__LIBSRVKIT_MONITOR_FUNC_H__

