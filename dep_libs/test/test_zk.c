#include <zookeeper.h>
#include <zookeeper_log.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

void global_watcher(zhandle_t* zkhandle, int type, int state, const char* path, void* ctx)
{
	pid_t tid = syscall( __NR_gettid );
	printf("global_watcher type:%d tid:%d\n", type, tid);

	if(type == ZOO_SESSION_EVENT){
		if(state == ZOO_CONNECTED_STATE){
			printf("connect to zookeeper ok!\n");
		}else if(state == ZOO_EXPIRED_SESSION_STATE){
			printf("session expired!\n");
		}
	}
}

void do_stat_completion(int rc, const struct Stat* stat, const void* data)
{
	printf("do_stat_completion:%d\n", rc);
}

void test_watch_awexists(zhandle_t* zkhandle);
void do_test_watch_exist(zhandle_t* zkhandle, int type, int state, const char* path, void * ctx)
{
	printf("do_test_watch_exist occured\n");
	pid_t tid = syscall( __NR_gettid );
	printf("pid:%d\n", tid);

	if(state == ZOO_CONNECTED_STATE){
		if(type == ZOO_DELETED_EVENT){
			printf("path:%s deleted\n", path);
		}else if(type == ZOO_CREATED_EVENT){
			printf("path:%s created\n", path);
		}
	}

	test_watch_awexists(zkhandle);
}


void test_watch_awexists(zhandle_t* zkhandle)
{
	printf("watch awexists\n");
	char* ctx = strdup("do_watch");
	int rc = zoo_awexists(zkhandle, "/test_zk", do_test_watch_exist, ctx, do_stat_completion, "do_completion");
	if(rc != ZOK){
		printf("error:%d for awexists\n", rc);
		return;
	}
}

void test_watch_awget(zhandle_t* zkhandle);
void do_test_watch_awget(zhandle_t* zkhandle, int type, int state, const char* path, void * ctx)
{
	pid_t tid = syscall( __NR_gettid );
	printf("do_test_watch_awget occured in pid:%d type:%d, state:%d, path:%s ctx:%s\n", tid, type, state, path, (char*)ctx);
	test_watch_awget(zkhandle);
}

void do_stat_awget_completion(int rc, const char* value, int value_len, const struct Stat* stat, const void* data)
{
	pid_t tid = syscall( __NR_gettid );
	printf("do_stat_awget_completion in tid:%d rc:%d value:%s, data:%s\n", tid, rc, value, (const char*)data);
}

void test_watch_awget(zhandle_t* zkhandle)
{
	char* ctx = strdup("do_watch_awget");
	int rc = zoo_awget(zkhandle, "/test_zk", do_test_watch_awget, ctx, do_stat_awget_completion, "do_completion");
	if(rc != ZOK){
		printf("error:%d for awget\n", rc);
		return;
	}
}

int main(int arg, char** argv)
{
	const char* host = "127.0.0.1:2181";
	int timeout = 3000;

	pid_t tid = syscall( __NR_gettid );
	printf("pid:%d\n", tid);
	zoo_set_debug_level(ZOO_LOG_LEVEL_WARN);

	char* ctx = strdup("test_watcher_d");
	zhandle_t* zkhandle = zookeeper_init(host, global_watcher, timeout, 0, ctx, 0);
	//zhandle_t* zkhandle = zookeeper_init(host, NULL, timeout, 0, NULL, 0);
	if(NULL == zkhandle){
		printf("failed to connect to zk\n");
	}
	/*
	while(zoo_state(zkhandle) != ZOO_CONNECTED_STATE){
		sleep(1);
	}

	printf("connected\n");

	char buffer[4096];
	int len = sizeof(4096);
	int rc = zoo_get(zkhandle, "/test_zk", 0, buffer, &len, NULL);
	if(rc != ZOK){
		printf("failed to get content from zk\n");
	}else{
		buffer[len] = 0;
		printf("content:%s\n", buffer);
	}

	char path[1024];
	struct String_vector strings;
	zoo_get_children(zkhandle, "/test_zk", 0, &strings);
	for(int i = 0; i <strings.count; ++i){
		printf("%s \t", strings.data[i]);
		sprintf(path, "/test_zk/%s", strings.data[i]);
		zoo_get(zkhandle, path, 0, buffer, &len, NULL);
		buffer[len] = 0;
		printf("%s\n", buffer);
	}
	printf("\n");
	*/

	//test_watch_awexists(zkhandle);
	test_watch_awget(zkhandle);
	getchar();
	zookeeper_close(zkhandle);
}
