#ifndef __LANCER_H__
#define __LANCER_H__
#include <pthread.h>
#include <sys/types.h>     
#include <sys/socket.h>
#include <netinet/in.h> 

enum Facility
{
    KERNEL_MESSAGES            = 0,
    USER_LEVEL_MESSAGES        = 1,
    MAIL_SYSTEM                = 2,
    SYSTEM_DAEMONS             = 3,
    SECURITY_MESSAGES_NOTE1    = 4,
    MESSAGES_GENERATED_SYSLOGD = 5,
    LINE_PRINTER_SUBSYSTEM     = 6,
    NETWORK_NEWS_SUBSYSTEM     = 7,
    UUCP_SUBSYSTEM             = 8,
    CLOCK_DAEMON               = 9,
    SECURITY_MESSAGES_NOTE2    = 10,
    FTP_DAEMON                 = 11,
    NTP_SUBSYSTEM              = 12,
    LOG_AUDIT_NOTE1            = 13,
    LOG_ALERT_NOTE1            = 14,
    CLOCK_DAEMON_NOTE2         = 15,
    LOCAL_USER_0               = 16,
    LOCAL_USER_1               = 17,
    LOCAL_USER_2               = 18,
    LOCAL_USER_3               = 19,
    LOCAL_USER_4               = 20,
    LOCAL_USER_5               = 21,
    LOCAL_USER_6               = 22,
    LOCAL_USER_7               = 23
};

enum Severity
{
    Emergency     = 0,
    Alert         = 1,
    Critical      = 2,
    Error         = 3,
    Warning       = 4,
    Notice        = 5,
    Informational = 6,
    Debug         = 7
};

typedef struct lancer_cli_t
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addrlen;
}lancer_cli_t;

int util_init_lancer(const char* ip_port);
void util_lancer_log(int task_id, const char* hostname, const char* fmt, ...);


#endif//__LANCER_H__

