#include <util_lancer.h>

#include <bim_util.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h> 

static lancer_cli_t* g_lancer_cli = NULL;
//g_lancer_cli->addr.sin_port = htons(15142);
//inet_pton(AF_INET, "172.16.113.149", &g_lancer_cli->addr.sin_addr);
int util_init_lancer(const char* ip_port)// const char* lancer_host, int lancer_port)
{
	if(!ip_port){
		return 0;
	}

	char lancer_host[128] = {0};
	int lancer_port = 0;
	int cnt = sscanf(ip_port, "%[^':']:%d", lancer_host, &lancer_port); 
	if(cnt != 2){
		LOG_ERR("invalid lancer ip port:%s", ip_port);
		return 0;
	}

	g_lancer_cli = (lancer_cli_t*)calloc(1, sizeof(lancer_cli_t));
	if(NULL == g_lancer_cli){
		return 0;
	}

	g_lancer_cli->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(g_lancer_cli->fd < 0){
		LOG_ERR("socket error, errno: %d", errno);
		free(g_lancer_cli);
		g_lancer_cli = NULL;
		return 0;
	}

	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	setsockopt(g_lancer_cli->fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

	int flag = fcntl(g_lancer_cli->fd, F_GETFL);
	fcntl(g_lancer_cli->fd, F_SETFL, flag|O_NONBLOCK);

	g_lancer_cli->addr.sin_family = AF_INET;
	g_lancer_cli->addr.sin_port = htons(lancer_port);
	inet_pton(AF_INET, lancer_host, &g_lancer_cli->addr.sin_addr);

	g_lancer_cli->addrlen = sizeof(g_lancer_cli->addr);
	return 0;
}

void util_lancer_log(int task_id, const char* hostname, const char* fmt, ...)
{
	if(!g_lancer_cli){
		return;
	}

	int pri = USER_LEVEL_MESSAGES * 8 + Informational;
    char date[32];
    time_t now_time = time(NULL);
	struct tm now_tm;
	localtime_r(&now_time, &now_tm);
	strftime(date, sizeof(date) - 1, "%h %d %H:%M:%S", &now_tm);

    char header[64];
    snprintf(header, sizeof(header) - 1, "%s %s ", date, hostname);

    char new_fmt[128];
    int idx = 0;
    char* f = const_cast<char*>(fmt);
    char* p = NULL;
    while((p = strstr(f + 1, "%")) != NULL){
        int len = p - f;
        strncpy(new_fmt + idx, f, len);
        idx += len;
        len = snprintf(new_fmt + idx, sizeof(new_fmt) - idx - 1, "%c", '\u0001');
        idx += len;
        f = p;
    }
    snprintf(new_fmt + idx, sizeof(new_fmt) - idx - 1, "%s", f);

	int buff_len = 8096;
    char* lancer_msg  = (char*)malloc(buff_len);
	if(!lancer_msg){
		return;
	}

	lancer_msg[buff_len-1] = 0;
    int msg_len = snprintf(lancer_msg, buff_len, "<%d>%s: %06d%lu", pri, header, task_id, now_time * 1000);
    va_list args;
    va_start(args, fmt);
    msg_len += vsnprintf(lancer_msg+msg_len, buff_len-msg_len-1, new_fmt, args);
    va_end(args);
    sendto(g_lancer_cli->fd, lancer_msg, msg_len, 0, (struct sockaddr*)&g_lancer_cli->addr, g_lancer_cli->addrlen);
	free(lancer_msg);
}
