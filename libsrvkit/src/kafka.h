#ifndef __LIBSRVKIT_KAFKA_H__
#define __LIBSRVKIT_KAFKA_H__
#include <list.h>
#include <server_inner.h>
#include <pthread.h>
#include <semaphore.h>
#include <config.pb.h>
#include <async_task.h>

enum kafka_msg_format
{
	en_kafka_pb_msg = 1,
	en_kafka_json_msg = 2,
};

typedef struct libsrvkit_kafka_consumer_t
{
	server_t* server;
	char* group_id;
	char* broker_list;
	int num_topics;
	char** topics;
	kafka_msg_format msg_format;
	char* consume_progress_redis;
	int thread_num;
	pthread_t* threads;
	list_head list;
	async_routine_t* async_progress;
}libsrvkit_kafka_consumer_t;

typedef struct rd_kafka_producer_req_t
{
	char sz_topic[64];
	char* payload;
	size_t len;
	list_head req_list;
	rpc_ctx_t* ctx;
	bool sync;
}rd_kafka_producer_req_t;

typedef struct rd_kafka_opaque_t
{
	worker_thread_t* dummy_worker;
	rpc_ctx_t* ctx;
	bool sync;
	async_routine_t* async_progress;
}rd_kafka_opaque_t;

typedef struct progress_data_t
{
	worker_thread_t* worker;
	char key[64];
	int last_offset;
	uint64_t last_update_time;
}progress_data_t;

typedef struct libsrvkit_kafka_produecer_t
{
	server_t* server;
	char* producer_id;
	char* broker_list;
	int num_topics;
	char** topics;
	kafka_msg_format msg_format;
	char* produce_progress_redis;

	int thread_num;
	pthread_t* threads;
	int max_queue_size;
	int* queue_size;
	list_head* req_queue;
	pthread_mutex_t* mutexs;
	sem_t* sem_ids;

	async_routine_t* async_progress;

	list_head list;
}libsrvkit_kafka_produecer_t;

typedef struct rdkafka_msg_cmd_t
{
	int format;
	char* payload;
	int len;
}rdkafka_msg_cmd_t;

libsrvkit_kafka_consumer_t* libsrvkit_malloc_consumer(server_t* server, const blink::pb_kafka_consumer& conf);
libsrvkit_kafka_produecer_t* libsrvkit_malloc_producer(server_t* server,  const blink::pb_kafka_producer& conf);

int init_kafka_consumer(server_t* server);
int init_kafka_producer(server_t* server);

void run_kafka_consumers(server_t* server);
void run_kafka_producers(server_t* server);

int async_produce_kafka_msg(rpc_ctx_t* ctx, const char* producer_id, const char* topic, const char* payload, size_t len); 
int sync_produce_kafka_msg(rpc_ctx_t* ctx, const char* producer_id, const char* topic, const char* payload, size_t len); 

int fn_on_recv_kafka_msg(void* arg);
void async_fin_kafka_dr(rpc_ctx_t* ctx);
#endif//__LIBSRVKIT_KAFKA_H__

