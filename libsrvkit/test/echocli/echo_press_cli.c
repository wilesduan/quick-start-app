#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <util_socket.h>
#include <util_fcntl.h>
#include <blink.pb.h>
#include <string>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

#include <gen_echo_mid_srv.pb.h>

#include <sys/types.h>
#include <sys/socket.h>

static char* server_ip = NULL;
static int server_port = 0;
static int thread_num = 1;
static int num_request = 1;

static uint64_t get_milli_second()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec*1000+tv.tv_usec/1000;
}


static void parse_argv(int argc, char** argv)
{
	int c = 0;
	while(-1 != (c = getopt(argc, argv, 
				 "i:"//server ip
				 "p:"//server port
				 "c:"//concurrency
				 "n:"//number per thread
				 "h"//show  help
		))){
		switch(c){
			case 'i':
				{
					server_ip = strdup(optarg);
					break;
				}
			case 'p':
				{
					server_port = atoi(optarg);
					break;
				}
			case 'c':
				{
					thread_num = atoi(optarg);
					break;
				}

			case 'n':
				{
					num_request = atoi(optarg);
					break;
				}
			case 'h':
				{
					printf("%s -i [server_ip] -p [server_port] -c [concurrency] -n [number per thread]\n", argv[0]);
					break;
				}
			default:
				{
					break;
				}
		}
	}
}


void* echo(void* arg)
{
	int fd = util_connect_2_svr(server_ip, server_port);
	if(fd <= 0){
		printf("failed to connect to srv\n");
		return 0;
	}
	util_un_fcntl(fd);

	blink::MsgBody body;
	body.set_call_type(blink::EN_MSG_TYPE_REQUEST);
	body.set_ss_req_id(0);

	//body.set_service("echosrv");
	body.set_service("mid_echo_srv");
	body.set_method(1);

	mid_echo_srv::mid_echo_request req;
	req.set_content("hello");
	std::string str_content;
	req.SerializeToString(&str_content);
	body.set_payload(str_content.c_str(), str_content.size());

	blink::MsgHead head;
	head.set_len(body.ByteSize());
	head.set_crc(0);

	std::string str_body;
	body.SerializeToString(&str_body);

	std::string str_head;
	head.SerializeToString(&str_head);

	str_head.append(str_body);

	uint64_t start = get_milli_second();
	char buff[102400];
	for(int i = 0; i < num_request; ++i){
		int rc = send(fd, str_head.c_str(), str_head.size(), 0);
		if(rc <= 0){
			perror("faield to send data to fd\n");
			exit(0);
			return NULL;
		}

		//continue;

		int len = recv(fd, buff, 1024, 0);
		if(len <= 0){
			perror("faield to recv data from fd\n");
			assert(0);
			return NULL;
		}

		head.set_len(0);
		head.set_crc(0);

		int head_len = head.ByteSize();
		bool parse = head.ParseFromArray(buff, head_len);
		if(!parse || head.len() == 0 || len < head.ByteSize() + head.len()){
			perror("failed recv return\n");
			assert(0);
			return NULL;
		}

		body.ParseFromArray(buff+head.ByteSize(), head.len());
		mid_echo_srv::mid_echo_response rsp;
		rsp.ParseFromArray(body.payload().c_str(), body.payload().size());
	}

	printf("tid:%llu totoal cost：%llu\n", pthread_self(), get_milli_second()-start);

	close(fd);

	return NULL;
}

#if 0
void* echo_test(void* arg)
{
	echo();
	return NULL;
}
#endif

int main(int argc, char** argv)
{
	parse_argv(argc, argv);
	if(server_ip == NULL || server_port <=0){
		printf("%s -i [server_ip] -p [server_port]\n", argv[0]);
		return 0;
	}

	/*
	for(int i = 0; i < 100000; ++i)
		echo(&i);
	return 0;
	*/

	pthread_t* pids = (pthread_t*)calloc(thread_num, sizeof(pthread_t));;
	for(int i= 0; i < thread_num; ++i){
		pthread_create((pids + i), NULL, echo, NULL);
	}

	for(int i = 0; i < thread_num; ++i){
		pthread_join(pids[i], NULL);
	}

	return 0;
}
