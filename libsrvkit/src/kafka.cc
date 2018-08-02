#include <kafka.h>
#include <bim_util.h>
#include <rdkafka.h>
#include <signal.h>
#include <map>
#include <redis.h>
#include <stdarg.h>

static void run_one_consumer(libsrvkit_kafka_consumer_t* consumer);
static void run_one_producer(libsrvkit_kafka_produecer_t* producer);
static void call_progress_reids(worker_thread_t* dummy_worker, const char* fmt, ...);

libsrvkit_kafka_consumer_t* libsrvkit_malloc_consumer(server_t* server, json_object* conf)
{
	json_object* js_group = NULL;
	json_object_object_get_ex(conf, "group.id", &js_group);
	if(NULL == js_group){
		LOG_ERR("miss group.id in kafka consumer config");
		return NULL;
	}

	json_object* js_broker_list = NULL;
	json_object_object_get_ex(conf, "broker_list", &js_broker_list);
	if(NULL == js_broker_list){
		LOG_ERR("miss broker list in kafka consumer config");
		return NULL;
	}

	json_object* js_topics = NULL;
	json_object_object_get_ex(conf, "topics", &js_topics);
	if(NULL == js_topics || !json_object_array_length(js_topics)){
		LOG_ERR("miss topics in kafka consumer config");
		return NULL;
	}

	json_object* js_format = NULL;
	json_object_object_get_ex(conf, "format", &js_format);

	json_object* js_consume_progress_redis = NULL;
	json_object_object_get_ex(conf, "redis", &js_consume_progress_redis);

	json_object* js_thread_num = NULL;
	json_object_object_get_ex(conf, "thread_num", &js_thread_num);

	libsrvkit_kafka_consumer_t* consumer = (libsrvkit_kafka_consumer_t*)calloc(1, sizeof(libsrvkit_kafka_consumer_t));
	if(NULL == consumer){
		LOG_ERR("failed to alloc mem for consumer");
		return NULL;
	}
	consumer->server = server;
	consumer->group_id = strdup(json_object_get_string(js_group));
	consumer->broker_list = strdup(json_object_get_string(js_broker_list));

	unsigned size = json_object_array_length(js_topics);
	consumer->topics = (char**)calloc(size, sizeof(char*));
	for(unsigned i = 0; i < size; ++i){
		(consumer->topics)[i] = strdup(json_object_get_string(json_object_array_get_idx(js_topics, i)));
	}
	consumer->num_topics = size;

	consumer->msg_format = en_kafka_pb_msg;
	if(!strcmp(json_object_get_string(js_format), "json")){
		consumer->msg_format = en_kafka_json_msg;
	}

	if(js_consume_progress_redis){
		consumer->consume_progress_redis = strdup(json_object_get_string(js_consume_progress_redis));
	}

	consumer->thread_num = 1;
	if(js_thread_num){
		consumer->thread_num = json_object_get_int(js_thread_num);
		consumer->thread_num = consumer->thread_num<=0?1:consumer->thread_num;
	}

	consumer->threads = (pthread_t*)calloc(consumer->thread_num, sizeof(pthread_t));
	INIT_LIST_HEAD(&consumer->list);
	return consumer;
}


int init_kafka_consumer(server_t* server)
{
	json_object* kafka = NULL;
	json_object_object_get_ex(server->config, "kafka", &kafka);
	if(NULL == kafka){
		return 0;
	}

	json_object* consumers = NULL;
	json_object_object_get_ex(kafka, "consumers", &consumers);
	if(NULL == consumers){
		return 0;
	}

	unsigned size = json_object_array_length(consumers);
	for(unsigned i = 0; i < size; ++i){
		json_object* inst = json_object_array_get_idx(consumers, i);
		libsrvkit_kafka_consumer_t* consumer = libsrvkit_malloc_consumer(server, inst);
		if(NULL == consumer){
			LOG_ERR("failed to create kafka consumer:%d", i);
			continue;
		}

		list_add(&consumer->list, &server->kafka_consumers);
	}

	return 0;
}

int init_kafka_producer(server_t* server)
{
	json_object* kafka = NULL;
	json_object_object_get_ex(server->config, "kafka", &kafka);
	if(NULL == kafka){
		return 0;
	}

	json_object* producers = NULL;
	json_object_object_get_ex(kafka, "producers", &producers);
	if(!producers){
		return 0;
	}

	unsigned size = json_object_array_length(producers);
	for(unsigned i = 0; i < size; ++i){
		json_object* inst = json_object_array_get_idx(producers, i);
		libsrvkit_kafka_produecer_t* producer = libsrvkit_malloc_producer(server, inst);
		if(NULL == producer){
			LOG_ERR("failed to create kafka producer:%d", i);
			continue;
		}

		list_add(&producer->list, &server->kafka_producers);
	}

	return 0;
}

void run_kafka_consumers(server_t* server)
{
	list_head* p = NULL;
	list_for_each(p, &(server->kafka_consumers)){
		libsrvkit_kafka_consumer_t* consumer = list_entry(p, libsrvkit_kafka_consumer_t, list);
		run_one_consumer(consumer);
	}
}

libsrvkit_kafka_produecer_t* libsrvkit_malloc_producer(server_t* server, json_object* conf)
{
	json_object* js_broker_list = NULL;
	json_object_object_get_ex(conf, "broker_list", &js_broker_list);
	if(NULL == js_broker_list){
		LOG_ERR("miss broker list in kafka producer config");
		return NULL;
	}

	json_object* js_producer_id = NULL;
	json_object_object_get_ex(conf, "id", &js_producer_id);
	if(NULL == js_producer_id){
		LOG_ERR("miss producer id in kafka producer config");
		return NULL;
	}

	json_object* js_topics = NULL;
	json_object_object_get_ex(conf, "topics", &js_topics);
	if(NULL == js_topics || !json_object_array_length(js_topics)){
		LOG_ERR("miss topics in kafka producer config");
		return NULL;
	}

	json_object* js_format = NULL;
	json_object_object_get_ex(conf, "format", &js_format);

	json_object* js_produce_progress_redis = NULL;
	json_object_object_get_ex(conf, "redis", &js_produce_progress_redis);

	json_object* js_thread_num = NULL;
	json_object_object_get_ex(conf, "thread_num", &js_thread_num);

	json_object* js_max_queue_size = NULL;
	json_object_object_get_ex(conf, "max_queue_size", &js_max_queue_size);

	libsrvkit_kafka_produecer_t* producer = (libsrvkit_kafka_produecer_t*)calloc(1, sizeof(libsrvkit_kafka_produecer_t));
	if(NULL == producer){
		LOG_ERR("failed to alloc mem for producer");
		return NULL;
	}

	producer->server = server;
	producer->broker_list = strdup(json_object_get_string(js_broker_list));
	producer->producer_id = strdup(json_object_get_string(js_producer_id));
	producer->max_queue_size = 100000;
	if(js_max_queue_size && json_object_get_int(js_max_queue_size) > 0){
		producer->max_queue_size = json_object_get_int(js_max_queue_size);
	}

	unsigned size = json_object_array_length(js_topics);
	producer->topics = (char**)calloc(size, sizeof(char*));
	for(unsigned i = 0; i < size; ++i){
		(producer->topics)[i] = strdup(json_object_get_string(json_object_array_get_idx(js_topics, i)));
	}
	producer->num_topics = size;

	producer->thread_num = 1;
	if(js_thread_num){
		producer->thread_num = json_object_get_int(js_thread_num);
		producer->thread_num = producer->thread_num<=0?1:producer->thread_num;
	}

	producer->queue_size = (int*)calloc(producer->thread_num, sizeof(int));
	producer->req_queue = (list_head*)calloc(producer->thread_num, sizeof(list_head));
	producer->mutexs = (pthread_mutex_t*)calloc(producer->thread_num, sizeof(pthread_mutex_t));
	producer->sem_ids = (sem_t*)calloc(producer->thread_num, sizeof(sem_t));
	for(int i = 0; i < producer->thread_num; ++i){
		INIT_LIST_HEAD(&((producer->req_queue)[i]));
		pthread_mutex_init(&((producer->mutexs)[i]), NULL);
		sem_init(&((producer->sem_ids)[i]), 0, 0);
	}

	producer->msg_format = en_kafka_pb_msg;
	if(!strcmp(json_object_get_string(js_format), "json")){
		producer->msg_format = en_kafka_json_msg;
	}

	if(js_produce_progress_redis){
		producer->produce_progress_redis= strdup(json_object_get_string(js_produce_progress_redis));
	}


	producer->threads = (pthread_t*)calloc(producer->thread_num, sizeof(pthread_t));
	INIT_LIST_HEAD(&producer->list);
	return producer;
}

void run_kafka_producers(server_t* server)
{
	list_head* p = NULL;
	list_for_each(p, &(server->kafka_producers)){
		libsrvkit_kafka_produecer_t* producer = list_entry(p, libsrvkit_kafka_produecer_t, list);
		run_one_producer(producer);
	}
}

static void logger (const rd_kafka_t *rk, int level, const char *fac, const char *buf) 
{
	LOG_WARN("RDKAFKA-%i-%s: %s: %s", level, fac, rd_kafka_name(rk), buf);
}

static void print_partition_list(const rd_kafka_topic_partition_list_t* partitions)
{
	for (int i = 0 ; i < partitions->cnt ; i++) {
		//LOG_INFO("%s %s [%"PRId32"] offset %"PRId64, i > 0 ? ",":"", partitions->elems[i].topic, partitions->elems[i].partition, partitions->elems[i].offset);
	}
}

static void rebalance_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,rd_kafka_topic_partition_list_t *partitions,void *opaque)
{
	switch (err){
		case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
			LOG_ERR("assign partitions");
			print_partition_list(partitions);
			rd_kafka_assign(rk, partitions);
			break;
		case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
			print_partition_list(partitions);
			rd_kafka_assign(rk, NULL);
			break;
		default:
			LOG_ERR("failed %s", rd_kafka_err2str(err));
			rd_kafka_assign(rk, NULL);
			break;
	}
}

static void notify_worker_kafka_msg(libsrvkit_kafka_consumer_t* consumer, const void* payload, size_t len)
{
	char* buff = (char*)malloc(len);
	if(NULL == buff){
		return;
	}

	rdkafka_msg_cmd_t cmd;
	cmd.format = consumer->msg_format;
	cmd.payload = buff;
	memcpy(cmd.payload, payload, len);
	cmd.len = len;
	int idx = random()%(consumer->server->num_worker);
	worker_thread_t* wt = consumer->server->array_worker + idx;
	size_t write_len = 0;
	int rc = 0;
	while(write_len < sizeof(cmd)){
		rc = write(wt->kafka_pipefd[1], (char*)(&cmd)+write_len, sizeof(cmd)-write_len);
		if(rc == 0){
			usleep(1000);//1ms
			continue;
		}

		if(rc < 0){
			free(buff);
			return;
		}

		write_len += rc;
		LOG_DBG("write cmd 2 kafka pipefd:%d:%d", rc, write_len);
	}

	/*
	int rc = write(wt->kafka_pipefd[1], &cmd, sizeof(cmd));
	if(rc != sizeof(cmd)){
		LOG_ERR("failed to notify worker");
		free(buff);
		return;
	}
	*/

	LOG_DBG("notify kafka msg to worker:%d:%llu", idx, (long long unsigned)wt);
}

static void msg_consume (libsrvkit_kafka_consumer_t* consumer, rd_kafka_message_t *rkmessage, void *opaque) 
{
	if (rkmessage->err) {
		if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
			LOG_DBG("Consumer reached end of %s [%d] message queue at offset %llu", rd_kafka_topic_name(rkmessage->rkt), rkmessage->partition, rkmessage->offset);
			return;
		}

		if (rkmessage->rkt){
			LOG_ERR("Consume error for topic:\"%s\" [%d] offset:%llu: %s", rd_kafka_topic_name(rkmessage->rkt), rkmessage->partition, rkmessage->offset, rd_kafka_message_errstr(rkmessage));
		}else{
			LOG_ERR("Consumer error: %s: %s", rd_kafka_err2str(rkmessage->err), rd_kafka_message_errstr(rkmessage));
		}
		return;
	}

	LOG_INFO("RDKAFKA Message (topic %s [%d] offset %llu %zd bytes", rd_kafka_topic_name(rkmessage->rkt), rkmessage->partition, rkmessage->offset, rkmessage->len);
	notify_worker_kafka_msg(consumer, rkmessage->payload, rkmessage->len);
	call_progress_reids((worker_thread_t*)opaque, "hmset kafka_consume_offset_%s_%s_%d last_offset %d last_update_time %lld", consumer->group_id, rd_kafka_topic_name(rkmessage->rkt), rkmessage->partition, rkmessage->offset, time(NULL));
}

static void* pthread_kafka_consumer(void* arg)
{
	libsrvkit_kafka_consumer_t* consumer = (libsrvkit_kafka_consumer_t*)arg;
	worker_thread_t dummy_worker;
	if(consumer->consume_progress_redis && connect_2_real_redis(&(dummy_worker.redis), consumer->consume_progress_redis)){
		LOG_ERR("failed to connect to progress redis:%s", consumer->consume_progress_redis);
	}

	char errstr[512];
	char tmp[16];
	rd_kafka_resp_err_t err;
	rd_kafka_conf_t *conf = rd_kafka_conf_new();;
	rd_kafka_topic_conf_t *topic_conf = rd_kafka_topic_conf_new();;
	rd_kafka_topic_partition_list_t *topics = rd_kafka_topic_partition_list_new(consumer->num_topics);
	rd_kafka_t *rk = NULL;
	rd_kafka_message_t *rkmessage = NULL;
	int run;

	rd_kafka_conf_set_log_cb(conf, logger);
	snprintf(tmp, sizeof(tmp), "%i", SIGIO);
	rd_kafka_conf_set(conf, "internal.termination.signal", tmp, NULL, 0);
	if(rd_kafka_conf_set(conf, "group.id", consumer->group_id, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK){
		LOG_ERR("failed to set group id:%s:%s", consumer->group_id, errstr);
		goto end;
	}

	if(rd_kafka_topic_conf_set(topic_conf, "offset.store.method", "broker", errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK){
		LOG_ERR("failed to set topic conf:%s", errstr);
		goto end;
	}

	rd_kafka_conf_set_default_topic_conf(conf, topic_conf);
	rd_kafka_conf_set_rebalance_cb(conf, rebalance_cb);

	rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf,errstr, sizeof(errstr));
	if(!rk){
		LOG_ERR("failed to create kafka");
		goto end;
	}
	if(!rd_kafka_brokers_add(rk, consumer->broker_list)){
		LOG_ERR("failed to add broker to rd_kafka. brokers:%s", consumer->broker_list);
		goto end;
	}

	for(int i = 0; i < consumer->num_topics; ++i){
		rd_kafka_topic_partition_list_add(topics, consumer->topics[i], -1);
	}

	if((err = rd_kafka_subscribe(rk, topics))){
		LOG_ERR("failed to subscrible to topics");
		goto end;
	}

	while(!consumer->server->exit){
		rkmessage = rd_kafka_consumer_poll(rk, 1000);
		if(rkmessage){
			msg_consume(consumer, rkmessage, &dummy_worker);
			rd_kafka_message_destroy(rkmessage);
		}
	}

	err = rd_kafka_consumer_close(rk);
	if(err){
		LOG_ERR("failed to close consumer:%s", rd_kafka_err2str(err));
	}else{
		LOG_INFO("close consumer success");
	}

end:
	if(conf) rd_kafka_conf_destroy(conf);
	if(topic_conf)rd_kafka_topic_conf_destroy(topic_conf);
	if(topics) rd_kafka_topic_partition_list_destroy(topics);
	if(rk) rd_kafka_destroy(rk);

	run = 5;
	while (run-- > 0 && rd_kafka_wait_destroyed(1000) == -1){
		LOG_ERR("Waiting for librdkafka to decommission");
	}

	return NULL;
}

static void run_one_consumer(libsrvkit_kafka_consumer_t* consumer)
{
	for(int i = 0; i < consumer->thread_num; ++i){
		pthread_create(&(consumer->threads[i]), NULL, pthread_kafka_consumer, consumer);
	}
}

static void free_rd_kafka_producer_req(rd_kafka_producer_req_t* req)
{
	if(!req) return;
	/*freed by kafka
	if(req->payload){
		free(req->payload);
	}
	*/

	free(req);
}

static void dr_msg_cb (rd_kafka_t *rk,const rd_kafka_message_t *rkmessage, void *opaque)
{
	if(rkmessage->err){
		LOG_ERR("Message delivery failed: %s", rd_kafka_err2str(rkmessage->err));
		return;
	}

	LOG_INFO("Message delivered (topic:%s, %zd bytes, partition %d, offset:%d)", rd_kafka_topic_name(rkmessage->rkt), rkmessage->len, rkmessage->partition, rkmessage->offset);

	//TODO call redis
	worker_thread_t* dummy_worker= (worker_thread_t*)opaque;
	call_progress_reids(dummy_worker, "hmset kafka_publish_offset_%s_%d last_offset %d last_update_time %lld", rd_kafka_topic_name(rkmessage->rkt), rkmessage->partition, rkmessage->offset, time(NULL));
}

static void* pthread_kafka_producer(void* arg)
{
	sleep(1);
	libsrvkit_kafka_produecer_t* producer = (libsrvkit_kafka_produecer_t*)arg;
	worker_thread_t dummy_worker;
	if(producer->produce_progress_redis&& connect_2_real_redis(&dummy_worker.redis, producer->produce_progress_redis)){
		LOG_ERR("failed to connect to progress redis:%s", producer->produce_progress_redis);
	}

	std::map<std::string, rd_kafka_topic_t*> rkts;
	rd_kafka_t *rk = NULL;
	rd_kafka_topic_t *rkt = NULL;
	rd_kafka_conf_t *conf = NULL;
	char errstr[512];
	int idx = -1;
	sem_t* sem = NULL;
	std::string topic;

	conf = rd_kafka_conf_new();
	if(rd_kafka_conf_set(conf, "bootstrap.servers", producer->broker_list, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK){
		LOG_ERR("failed to set bootstrap.servers. brokers:%s", producer->broker_list);
		goto end;
	}

	rd_kafka_conf_set_opaque(conf, &dummy_worker);
	rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);
	rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	for(int i = 0; i < producer->num_topics; ++i){
		topic = producer->topics[i];
		if(rkts.find(topic) != rkts.end()){
			continue;
		}

		rkt  = rd_kafka_topic_new(rk, topic.c_str(), NULL);
		if(!rkt){
			LOG_ERR("failed to create kafka topic:%s", topic.c_str());
			continue;
		}

		rkts[topic] = rkt;
	}

	for(int i = 0; i < producer->thread_num; ++i){
		if(pthread_self() == producer->threads[i]){
			idx = i;
			break;
		}
	}

	if(idx == -1){
		LOG_ERR("failed to get my indx");
		assert(0);
	}

	sem = producer->sem_ids + idx;
	while(!producer->server->exit){
		sem_wait(sem);
		LOG_INFO("wait one msg");
		list_head* p = NULL;
		pthread_mutex_lock(producer->mutexs+idx);
		p = pop_list_node(producer->req_queue + idx);
		--(producer->queue_size[idx]);
		pthread_mutex_unlock(producer->mutexs+idx);

		rd_kafka_producer_req_t* req = list_entry(p, rd_kafka_producer_req_t, req_list);
		topic = req->sz_topic;
		if(rkts.find(topic) == rkts.end()){
			LOG_ERR("invalid topic:%s", req->sz_topic);
			free_rd_kafka_producer_req(req);
			continue;
		}
		rkt = rkts[topic];
retry:
		if (rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_FREE, req->payload, req->len, NULL, 0, &dummy_worker) == -1){
			LOG_ERR("Failed to produce to topic %s: %s", rd_kafka_topic_name(rkt), rd_kafka_err2str(rd_kafka_last_error()));
			if (rd_kafka_last_error() ==RD_KAFKA_RESP_ERR__QUEUE_FULL) {
				rd_kafka_poll(rk, 1000/*block for max 1000ms*/);
				goto retry;
			}
			if(req->payload)
				free(req->payload);
		}else{
			LOG_INFO("Enqueued message (%zd bytes) for topic:%s", req->len, rd_kafka_topic_name(rkt));
		}

		free_rd_kafka_producer_req(req);
		rd_kafka_poll(rk, 0/*non-blocking*/);
	}

	rd_kafka_flush(rk, 10*1000 /* wait for max 10 seconds */);

end:
	if(conf) rd_kafka_conf_destroy(conf);
	for(std::map<std::string, rd_kafka_topic_t*>::iterator it = rkts.begin(); it != rkts.end(); ++it){
		rd_kafka_topic_destroy(it->second);
	}

	return NULL;
}

static void run_one_producer(libsrvkit_kafka_produecer_t* producer)
{
	for(int i = 0; i < producer->thread_num; ++i){
		pthread_create(&(producer->threads[i]), NULL, pthread_kafka_producer, producer);
	}
}

static int put_data_to_queue(libsrvkit_kafka_produecer_t* producer, const char* topic, const char* payload, size_t len)
{
	if(strlen(topic) >= sizeof(((rd_kafka_producer_req_t*)0)->sz_topic)){
		LOG_ERR("topic:%s too long", topic);
		return -5;
	}

	int idx = random()%(producer->thread_num);
	if(producer->queue_size[idx] > producer->max_queue_size){
		LOG_ERR("producer queue full.%d:%d", producer->queue_size[idx], producer->max_queue_size);
		return -6;
	}

	rd_kafka_producer_req_t* req = (rd_kafka_producer_req_t*)calloc(1, sizeof(rd_kafka_producer_req_t));
	strcpy(req->sz_topic, topic);
	req->len = len;
	req->payload = (char*)malloc(len);
	INIT_LIST_HEAD(&req->req_list);
	memcpy(req->payload, payload, len);

	pthread_mutex_lock(producer->mutexs + idx);
	list_add_tail(&req->req_list, (producer->req_queue+idx));
	++(producer->queue_size[idx]);
	pthread_mutex_unlock(producer->mutexs + idx);
	sem_post(producer->sem_ids+idx);

	return 0;
}

int produce_kafka_msg(rpc_ctx_t* ctx, const char* producer_id, const char* topic, const char* payload, size_t len)
{
	server_t* server = (server_t*)(((worker_thread_t*)ctx->co->worker)->mt);
	libsrvkit_kafka_produecer_t* producer = NULL;
	list_head* p = NULL;
	list_for_each(p, &server->kafka_producers){
		libsrvkit_kafka_produecer_t* pr =  list_entry(p, libsrvkit_kafka_produecer_t, list);
		if(strcmp(producer_id, pr->producer_id) == 0){
			producer = pr;
			break;
		}
	}

	if(NULL == producer){
		LOG_ERR("no producer for id:%s", producer_id);
		return -1;
	}

	return put_data_to_queue(producer, topic, payload, len);
}

static void call_progress_reids(worker_thread_t* dummy_worker, const char* fmt, ...)
{
	prepare_redis_status(&(dummy_worker->redis), false);
	if(!dummy_worker->redis.client){
		LOG_DBG("no progress redis");
		return;
	}

	redisReply* reply = NULL;
	switch(dummy_worker->redis.type){
		case EN_REDIS_NONE:
			LOG_ERR("invalid redis type");
			return;
		case EN_REDIS_CLUSTER:
			{
				va_list args;
				va_start(args, fmt);
				reply = (redisReply*)redisClustervCommand((redisClusterContext*)(dummy_worker->redis.client), fmt, args);
				va_end(args);
			}
			break;
		case EN_REDIS_TW:
			{
				va_list args;
				va_start(args, fmt);
				reply = (redisReply*)redisvCommand((redisContext*)(dummy_worker->redis.client), fmt, args);
				va_end(args);
			}
			break;
	}

	if(NULL == reply || REDIS_REPLY_ERROR == reply->type){
		prepare_redis_status(&(dummy_worker->redis));
		LOG_ERR("failed to call redis");
	}

	if(reply){
		freeReplyObject(reply);
	}
}

int fn_on_recv_kafka_msg(void* arg)
{
	ev_ptr_t* ptr = (ev_ptr_t*)arg;
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	rdkafka_msg_cmd_t cmd;
	int len = 0;
	while((len = read(ptr->fd, &cmd, sizeof(cmd))) == sizeof(cmd)){
		LOG_DBG("recv kafka msg, worker:%llu, len:%d", (long long unsigned)worker, cmd.len);
		switch(cmd.format){
			case en_kafka_pb_msg:
				{
					blink::MsgBody body;
					bool succ = body.ParseFromArray(cmd.payload, cmd.len);
					if(!succ){
						LOG_ERR("failed to parse pb msg from kafka. len:%d", cmd.len);
						break;
					}

					process_pb_request(ptr, body);
				}
				break;
			case en_kafka_json_msg:
				{
					//TODO
					//process_swoole_request(ptr, );
				}
				break;
			default:
				break;
		}

		free(cmd.payload);
	}
	return 0;
}
