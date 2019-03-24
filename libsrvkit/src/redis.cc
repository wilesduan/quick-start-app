#include <redis.h>
#include <bim_util.h>
#include <dict.h>

#define K_PINT_REDIS_TIME 5

int g_use_cluster_redis = 0;
int g_sync_call_redis = 0;

static void free_redis_replys(redis_client_t* client);
static void free_redis_ctx(redis_ctx_t* ctx);

static int do_redis_cluster_cmd(void* ctx);
static int do_redis_tw_cmd(void* ctx);

static redis_client_t* get_redis_client(rpc_ctx_t* ctx)
{
	int flag_test = ctx->co->uctx.flag_test;
	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	redis_client_t* redis = flag_test?worker->redis.redis_4_test:&worker->redis;
	if(!redis){
		LOG_ERR("no redis 4 flag:%d", flag_test);
	}

	return redis;
}

redisReply* call_redis(rpc_ctx_t* ctx, const char* fmt, ...)
{
	bool async = g_sync_call_redis? false : ctx&&ctx->co&&ctx->co->pre;

	if(NULL == ctx || NULL == ctx->co || NULL == ctx->co->worker){
		LOG_ERR("no worker in ctx");
		return NULL;
	}

	if(!list_empty(&(ctx->redis_cmds.cmds))){
		LOG_ERR("has redis cmd not commit");
		return NULL;
	}

	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	free_redis_replys(&worker->redis);

	redis_ctx_t* redis_ctx = (redis_ctx_t*)calloc(1, sizeof(redis_ctx_t));
	INIT_LIST_HEAD(&(redis_ctx->list));
	va_list args;
	va_start(args, fmt);
	int len = redisvFormatCommand(&redis_ctx->fmt_cmd, fmt, args);
	va_end(args);

	if(len < 0){
		LOG_ERR("failed to format redis cmd");
		free_redis_ctx(redis_ctx);
		return NULL;
	}

	redis_ctx->len = len;
	list_add_tail(&(redis_ctx->list), &(ctx->redis_cmds.cmds));
	ctx->redis_cmds.start_ts = get_monotonic_milli_second();

	redis_client_t* redis = get_redis_client(ctx);
	if(!redis){
		free_redis_ctx(redis_ctx);
		return NULL;
	}

	ctx->redis = redis;

	switch(redis->type){
		case EN_REDIS_CLUSTER:
			{
				if(!async){
					do_redis_cluster_cmd(ctx);
					break;
				}

				int rc = add_task_2_routine(redis->asyncer, do_redis_cluster_cmd, ctx);
				if(rc){
					LOG_ERR("[REDIS_AYSNC_ALARM]failed to add async task to redis client");
					free_redis_ctx(redis_ctx);
					return NULL;
				}

				break;
			}
		case EN_REDIS_TW:
			{
				if(!async){
					do_redis_tw_cmd(ctx);
					break;
				}

				int rc = add_task_2_routine(redis->asyncer, do_redis_tw_cmd, (void*)(ctx));
				if(rc){
					LOG_ERR("[REDIS_AYSNC_ALARM]failed to add async task redis tw client");
					free_redis_ctx(redis_ctx);
					return NULL;
				}

				break;
			}
		default:
			free_redis_ctx(redis_ctx);
			return NULL;
	}

	if(async){
		co_yield(ctx->co);
	}

	uint64_t milli_cost = get_monotonic_milli_second() - ctx->redis_cmds.start_ts;
	MONITOR_ACC("cost_call_redis", milli_cost);
	MONITOR_ACC("qpm_call_redis", 1);
	MONITOR_MAX("cost_max_call_redis", milli_cost);
	if(redis_ctx->err){
	    char tmp_str[60];
	    snprintf(tmp_str, sizeof(tmp_str), "call_redis_error_%d", redis_ctx->err);
	    MONITOR_ACC(tmp_str, 1);
		LOG_ERR("call redis(%s:%d) error:%d=>%s", worker->redis.host, worker->redis.port, redis_ctx->err, redis_ctx->err_str);
	}

	list_del(&(redis_ctx->list));
	list_add_tail(&(redis_ctx->list), &(worker->redis.replys));
	return redis_ctx->reply;
}

redisReply* call_redisv(rpc_ctx_t* ctx, const std::vector<std::string>& cmds)
{
	bool async = g_sync_call_redis? false : ctx&&ctx->co&&ctx->co->pre;

	if(NULL == ctx || NULL == ctx->co || NULL == ctx->co->worker){
		LOG_ERR("no worker in ctx");
		return NULL;
	}

	if(!list_empty(&(ctx->redis_cmds.cmds))){
		LOG_ERR("has redis cmd not commit");
		return NULL;
	}

	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	free_redis_replys(&worker->redis);

	redis_ctx_t* redis_ctx = (redis_ctx_t*)calloc(1, sizeof(redis_ctx_t));
	INIT_LIST_HEAD(&(redis_ctx->list));

	std::vector<const char*> argv;
	std::vector<size_t> argvlen;
	for (size_t i = 0; i < cmds.size(); ++i) {
		argv.push_back(cmds[i].data());
		argvlen.push_back(cmds[i].size());
	}
	int len = redisFormatCommandArgv(&redis_ctx->fmt_cmd, cmds.size(), argv.data(), argvlen.data());
	if(len < 0){
		LOG_ERR("failed to format redis cmd");
		free_redis_ctx(redis_ctx);
		return NULL;
	}

	redis_ctx->len = len;
	list_add_tail(&(redis_ctx->list), &(ctx->redis_cmds.cmds));

	ctx->redis_cmds.start_ts = get_monotonic_milli_second();

	redis_client_t* redis = get_redis_client(ctx);
	if(!redis){
		free_redis_ctx(redis_ctx);
		return NULL;
	}

	ctx->redis = redis;

	switch(redis->type){
		case EN_REDIS_CLUSTER:
			{
				if(!async){
					do_redis_cluster_cmd(ctx);
					break;
				}

				int rc = add_task_2_routine(redis->asyncer, do_redis_cluster_cmd, ctx);
				if(rc){
					LOG_ERR("[REDIS_AYSNC_ALARM]failed to add async task to redis client");
					free_redis_ctx(redis_ctx);
					return NULL;
				}

				break;
			}
		case EN_REDIS_TW:
			{
				if(!async){
					do_redis_tw_cmd(ctx);
					break;
				}

				int rc = add_task_2_routine(redis->asyncer, do_redis_tw_cmd, (void*)(ctx));
				if(rc){
					LOG_ERR("[REDIS_AYSNC_ALARM]failed to add async task redis tw client");
					free_redis_ctx(redis_ctx);
					return NULL;
				}

				break;
			}
		default:
			free_redis_ctx(redis_ctx);
			return NULL;
	}

	if(async){
		co_yield(ctx->co);
	}

	uint64_t milli_cost = get_monotonic_milli_second() - ctx->redis_cmds.start_ts;
	MONITOR_ACC("cost_call_redisv", milli_cost);
	MONITOR_ACC("qpm_call_redisv", 1);
	MONITOR_MAX("cost_max_call_redisv", milli_cost);
	if(redis_ctx->err){
	    char tmp_str[60];
	    snprintf(tmp_str, sizeof(tmp_str), "call_redisv_error_%d", redis_ctx->err);
	    MONITOR_ACC(tmp_str, 1);
		LOG_ERR("call redis(%s:%d) error:%d=>%s", worker->redis.host, worker->redis.port, redis_ctx->err, redis_ctx->err_str);
	}

	list_del(&(redis_ctx->list));
	list_add_tail(&(redis_ctx->list), &(worker->redis.replys));
	return redis_ctx->reply;
}

int __connect_2_real_redis(redis_client_t* redis, const char* link)
{
	redis->redis_4_test = NULL;
	redis->asyncer = malloc_async_routines(1, 10000);
	run_async_routines(redis->asyncer, 1);
	INIT_LIST_HEAD(&(redis->replys));

	const char* p = link;
	while(*p != 0 && !isalpha(*p)){
		++p;
	}

	if(*p == 0)return 0;

	if(strncmp(p, "cluster://", 10) == 0){
		g_use_cluster_redis = 1;
		redis->type = EN_REDIS_CLUSTER;
		redis->passwd = NULL;
		const char* passwd = p+10;
		while(*passwd != 0 && *passwd != '/'){
			++passwd;
		}
		redis->host = strndup(p+10, passwd-p-10);
		if(*passwd == '/'){
			redis->passwd = strdup(passwd+1);
		}

		struct timeval tv = {0, 50000};
		redisClusterContext* ctx = redisClusterConnectWithTimeout(redis->host, tv, HIRCLUSTER_FLAG_NULL);
		if(NULL == ctx || ctx->err){
			LOG_ERR("failed to connect to:%s. err:%s", redis->host, ctx?ctx->errstr:"unknown");
			return -1;
		}

		tv.tv_usec = 200000;
		redisClusterSetOptionTimeout(ctx, tv);

		if(redis->passwd){
			redisReply* reply = (redisReply*)redisClusterCommand(ctx, "AUTH %s", redis->passwd);
			if (reply->type == REDIS_REPLY_ERROR) {
				LOG_ERR("failed to auth:%s:%d %s", redis->host, redis->port, redis->passwd);
				freeReplyObject(reply);
				return -2;
			}
			freeReplyObject(reply);
		}

		LOG_INFO("connect to redis:%s:%d success", redis->host, redis->port);
		redis->client = ctx;
        return 0;
	}else if(strncmp(p, "tw://", 5) == 0){
		redis->passwd = NULL;
		const char* prt = p+5;
		while(*prt != 0 && *prt != ':'){
			++prt;
		}
		if(*prt == 0){
			LOG_ERR("miss port. link:%s", link);
			return -2;
		}

		int port = atoi(prt+1);
		if(port <= 0){
			LOG_ERR("invalid redis server port:%s", link);
			return -2;
		}
		const char* passwd = prt+1;
		while(*passwd != 0 && *passwd != '/'){
			++passwd;
		}
		if(*passwd == '/'){
			redis->passwd = strdup(passwd+1);
			LOG_INFO("redis password:%s", redis->passwd);
		}

		redis->type = EN_REDIS_TW;
		redis->host = strndup(p+5, prt-p - 5);
		redis->port = port;
		struct timeval tv = {0, 50000};
		redisContext* ctx = redisConnectWithTimeout(redis->host, redis->port, tv);
		if(NULL == ctx || ctx->err){
			LOG_ERR("failed to connect to:%s:%d. err:%s", redis->host, redis->port, ctx?ctx->errstr:"unknown");
			return -3;
		}

		if(redis->passwd){
			redisReply* reply = (redisReply*)redisCommand(ctx, "AUTH %s", redis->passwd);
			if (reply->type == REDIS_REPLY_ERROR) {
				LOG_ERR("failed to auth:%s:%d %s", redis->host, redis->port, redis->passwd);
				freeReplyObject(reply);
				return -4;
			}
			freeReplyObject(reply);
		}

		tv.tv_usec = 200000;
		redisSetTimeout(ctx, tv);
		redis->client = ctx;
		redis->last_ping = time(NULL);

		LOG_INFO("connect to redis:%s:%d success", redis->host, redis->port);
        return 0;
	}

	LOG_ERR("only support cluster or tw redis. invalid link:%s", link);
	return -4;
}

int connect_2_real_redis(redis_client_t* redis, const char* link, const char* test_link)
{
	if(!redis){
		LOG_ERR("null redis");
		return -100;
	}

	int rc = __connect_2_real_redis(redis, link);
	if(rc){
		LOG_ERR("failed to connect to redis:%s", link);
		return rc;
	}

	if(!test_link){
		return 0;
	}

	redis->redis_4_test = (redis_client_t*)(calloc(1, sizeof(redis_client_t)));
	rc = __connect_2_real_redis(redis->redis_4_test, test_link);
	if(rc){
		LOG_ERR("failed to connect to test redis:%s", test_link);
	}

	return 0;
}

static void reconnect_redis(redis_client_t* redis)
{
	if(NULL == redis->host || EN_REDIS_NONE == redis->type){
		return;
	}

	if(redis->client){
		switch(redis->type){
			case EN_REDIS_CLUSTER:
				redisClusterFree((redisClusterContext*)(redis->client));
				redis->client = NULL;
				break;
			case EN_REDIS_TW:
				redisFree((redisContext*)(redis->client));
				redis->client = NULL;
				break;
			default:
				break;
		}
	}

	switch(redis->type){
		case EN_REDIS_CLUSTER:
			{
				struct timeval tv = {0, 50000};
				redisClusterContext* ctx = redisClusterConnectWithTimeout(redis->host, tv, HIRCLUSTER_FLAG_NULL);
				if(NULL == ctx || ctx->err){
					LOG_ERR("failed to connect to:%s. err:%s", redis->host, ctx?ctx->errstr:"unknown");
					break;
				}

				tv.tv_usec = 200000;
				redisClusterSetOptionTimeout(ctx, tv);

				if(redis->passwd){
					redisReply* reply = (redisReply*)redisClusterCommand(ctx, "AUTH %s", redis->passwd);
                    if (NULL == reply){
                        LOG_ERR("redisClusterCommand error,cmd:auth");
                        return;
                    }
					
					if (reply->type == REDIS_REPLY_ERROR) {
						LOG_ERR("failed to auth to reids: %s:%d passwd:%s", redis->host, redis->port, redis->passwd);
						freeReplyObject(reply);
						return;
					}
					freeReplyObject(reply);
				}

				redis->client = ctx;
			}
			break;
		case EN_REDIS_TW:
			{
				if(redis->port <= 0){
					break;
				}

				struct timeval tv = {0, 50000};
				redisContext* ctx = redisConnectWithTimeout(redis->host, redis->port, tv);
				if(NULL == ctx || ctx->err){
					LOG_ERR("failed to connect to:%s:%d. err:%s", redis->host, redis->port, ctx?ctx->errstr:"unknown");
					break;
				}

				if(redis->passwd){
					redisReply* reply = (redisReply*)redisCommand(ctx, "AUTH %s", redis->passwd);
                    if (NULL == reply){
                        LOG_ERR("redisCommand error,cmd:auth");
                        return;
                    }
					if (reply->type == REDIS_REPLY_ERROR) {
						LOG_ERR("failed to auth:%s:%d passwd%s", redis->host, redis->port, redis->passwd);
						freeReplyObject(reply);
						return;
					}
					freeReplyObject(reply);
				}

				tv.tv_usec = 200000;
				redisSetTimeout(ctx, tv);
				redis->client = ctx;
				redis->last_ping = time(NULL);
			}
			break;
		default:
			break;
	}

}

void prepare_redis_status(redis_client_t* redis, bool ping)
{
	if(!redis){
		return;
	}
	if(NULL == redis->client){
		reconnect_redis(redis);
	}

	if(!ping) return;

	if(NULL == redis->client)
		return;

	if(redis->type == EN_REDIS_CLUSTER){
		return;
	}
    redisContext* ctx = (redisContext*)(redis->client);

    if (ctx->err){
        LOG_ERR("reconnect_redis host:%s,port:%d", redis->host, redis->port);
        reconnect_redis(redis);
        return;
    }
 
    time_t now = time(NULL);
	if(now < redis->last_ping + K_PINT_REDIS_TIME){
		return;
	}
	redisReply* reply = (redisReply*)redisCommand(ctx, "PING hi");
	if(NULL == reply || REDIS_REPLY_ERROR == reply->type || NULL == reply->str|| strcmp(reply->str, "hi") != 0){
		reconnect_redis(redis);
	}else{
		redis->last_ping = now;
	}

	if(reply){
		freeReplyObject(reply);
	}
}

int begin_redis_pipeline(rpc_ctx_t* ctx)
{
	if(NULL == ctx || NULL == ctx->co || NULL == ctx->co->worker){
		LOG_ERR("no worker in ctx");
		return -1;
	}

	if(!list_empty(&(ctx->redis_cmds.cmds))){
		LOG_ERR("has redis cmd not commit");
		return -2;
	}

	ctx->redis_cmds.executed = 0;

	ctx->redis_cmds.start_ts = get_monotonic_milli_second();
	ctx->redis = get_redis_client(ctx);
	if(!ctx->redis){
		return -3;
	}

	return 0;
}

int call_add_pipeline_command(rpc_ctx_t* ctx, const char* fmt, ...)
{
	if(NULL == ctx || NULL == ctx->co || NULL == ctx->co->worker){
		LOG_ERR("no worker in ctx");
		return -1;
	}

	if(!ctx->redis){
		LOG_ERR("no redis in ctx");
		return -2;
	}

	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	free_redis_replys(&worker->redis);

	redis_ctx_t* redis_ctx = (redis_ctx_t*)calloc(1, sizeof(redis_ctx_t));
	INIT_LIST_HEAD(&(redis_ctx->list));
	va_list args;
	va_start(args, fmt);
	int len = redisvFormatCommand(&redis_ctx->fmt_cmd, fmt, args);
	va_end(args);
	if(len < 0){
		LOG_ERR("failed to format redis cmd");
		free_redis_ctx(redis_ctx);
		return -4;
	}

	redis_ctx->len = len;
	list_add_tail(&(redis_ctx->list), &(ctx->redis_cmds.cmds));
	return 0;
}

int call_add_pipeline_commandv(rpc_ctx_t* ctx, const std::vector<std::string>& cmds)
{
	if(NULL == ctx || NULL == ctx->co || NULL == ctx->co->worker){
		LOG_ERR("no worker in ctx");
		return -1;
	}

	if(!ctx->redis){
		LOG_ERR("no redis in ctx");
		return -2;
	}

	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	free_redis_replys(&worker->redis);

	redis_ctx_t* redis_ctx = (redis_ctx_t*)calloc(1, sizeof(redis_ctx_t));
	INIT_LIST_HEAD(&(redis_ctx->list));

	std::vector<const char*> argv;
	std::vector<size_t> argvlen;
	for (size_t i = 0; i < cmds.size(); ++i) {
		argv.push_back(cmds[i].data());
		argvlen.push_back(cmds[i].size());
	}
	int len = redisFormatCommandArgv(&redis_ctx->fmt_cmd, cmds.size(), argv.data(), argvlen.data());
	if(len < 0){
		LOG_ERR("failed to format redis cmd");
		free_redis_ctx(redis_ctx);
		return -4;
	}

	redis_ctx->len = len;
	list_add_tail(&(redis_ctx->list), &(ctx->redis_cmds.cmds));
	return 0;
}

redisReply* get_pipeline_reply(rpc_ctx_t* ctx)
{
	bool async = g_sync_call_redis? false : ctx&&ctx->co&&ctx->co->pre;

	if(NULL == ctx || NULL == ctx->co || NULL == ctx->co->worker){
		LOG_ERR("no worker in ctx");
		return NULL;
	}

	if(!ctx->redis){
		LOG_ERR("no redis in ctx");
		return NULL;
	}

	redis_client_t* redis = ctx->redis;

	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	free_redis_replys(&worker->redis);

	if(list_empty(&(ctx->redis_cmds.cmds))){
		return NULL;
	}

	int rc = 0;
	if(ctx->redis_cmds.executed){
		goto end_reply;
	}

	switch(worker->redis.type){
		case EN_REDIS_CLUSTER:
			{
				if(!async){
					do_redis_cluster_cmd(ctx);
					break;
				}

				rc = add_task_2_routine(redis->asyncer, do_redis_cluster_cmd, (void*)(ctx));
				if(rc){
					LOG_ERR("[REDIS_AYSNC_ALARM]failed to add ctx to redis asyncer");
					goto end_reply; 
				}
			}

			goto yeild_co;
			
		case EN_REDIS_TW:
			{
				if(!async){
					do_redis_tw_cmd(ctx);
					break;
				}
				rc = add_task_2_routine(redis->asyncer, do_redis_tw_cmd, (void*)(ctx));
				if(rc){
					LOG_ERR("[REDIS_AYSNC_ALARM]failed to add async task redis tw client");
					goto end_reply; 
				}
			}
			goto yeild_co;
		default:
			return NULL;
	}

yeild_co:
	if(async){
		co_yield(ctx->co);
	}

end_reply:
	list_head* p = pop_list_node(&ctx->redis_cmds.cmds);
	if(!p){
		return NULL;
	}
	redis_ctx_t* redis_ctx = list_entry(p, redis_ctx_t, list);
	list_add_tail(&(redis_ctx->list), &(worker->redis.replys));
	return redis_ctx->reply;

}

void end_redis_pipeline(rpc_ctx_t* ctx)
{
	if(NULL == ctx || NULL == ctx->co || NULL == ctx->co->worker){
		LOG_ERR("no worker in ctx");
		return;
	}

	while(!list_empty(&(ctx->redis_cmds.cmds))){
		get_pipeline_reply(ctx);
	}

	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	free_redis_replys(&worker->redis);

	uint64_t milli_cost = get_monotonic_milli_second() - ctx->redis_cmds.start_ts;
	MONITOR_ACC("cost_pipeline_call_redis", milli_cost);
	MONITOR_ACC("qpm_pipeline_call_redis", 1);
	MONITOR_MAX("cost_max_pipeline_call_redis", milli_cost);
}

static void free_redis_replys(redis_client_t* client)
{
	list_head* p; 
	list_head* n;
	list_for_each_safe(p, n, &client->replys){
		redis_ctx_t* c = list_entry(p, redis_ctx_t, list);
		free_redis_ctx(c);
	}

	if(!client->redis_4_test){
		return;
	}

	free_redis_replys(client->redis_4_test);
}

static void free_redis_ctx(redis_ctx_t* ctx)
{
	if(NULL == ctx){
		return;
	}

	if(ctx->fmt_cmd){
		free(ctx->fmt_cmd);
	}

	if(ctx->reply){
		freeReplyObject(ctx->reply);
		ctx->reply = NULL;
	}

	if(ctx->err_str){
		free(ctx->err_str);
	}

	list_del(&(ctx->list));
	free(ctx);
}

#if 0
static dictIterator* dict_get_iterator(dict* ht)
{
    dictIterator *iter = (dictIterator*)malloc(sizeof(*iter));

    iter->ht = ht;
    iter->index = -1;
    iter->entry = NULL;
    iter->nextEntry = NULL;
    return iter;
}

static void dict_release_iterator(dictIterator *iter)
{
    free(iter);
}

static dictEntry *dict_next(dictIterator *iter)
{
    while (1) {
        if (iter->entry == NULL) {
            iter->index++;
            if (iter->index >=
                    (signed)iter->ht->size) break;
            iter->entry = iter->ht->table[iter->index];
        } else {
            iter->entry = iter->nextEntry;
        }
        if (iter->entry) {
            /* We need to save the 'next' here, the iterator user
             * may delete the entry we are returning. */
            iter->nextEntry = iter->entry->next;
            return iter->entry;
        }
    }
    return NULL;
}

static int send_all_cluster_cmd(redisClusterContext* cc)
{
	if(!cc){
		return REDIS_ERR;
	}

    dictIterator *di;
    dictEntry *de;
    struct cluster_node *node;
    redisContext *c = NULL;
    int wdone = 0;
    
    if(cc == NULL || cc->nodes == NULL)
    {
        return REDIS_ERR;
    }

    di = dict_get_iterator(cc->nodes);
    while((de = dict_next(di)) != NULL)
    {
        node = (cluster_node*)dictGetEntryVal(de);
        if(node == NULL)
        {
            continue;
        }
        
        c = ctx_get_by_node(cc, node);
        if(c == NULL)
        {
            continue;
        }

        if (c->flags & REDIS_BLOCK) {
            /* Write until done */
            do {
                if (redisBufferWrite(c,&wdone) == REDIS_ERR)
                {
                    dict_release_iterator(di);
					c->err = REDIS_ERR;
					break;
                }
            } while (!wdone);
        }
    }
    
    dict_release_iterator(di);

    return REDIS_OK;
}
#endif

static int do_redis_cluster_cmd(void* arg)
{
	rpc_ctx_t* ctx = (rpc_ctx_t*)arg;
	ctx->redis_cmds.executed = 1;
	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	redis_client_t* redis = ctx->redis; 
	uint64_t nts = get_monotonic_milli_second();
	prepare_redis_status(redis);
	list_head* p = NULL;
	list_for_each(p, &(ctx->redis_cmds.cmds)){
		redis_ctx_t* redis_ctx = list_entry(p, redis_ctx_t, list);
		if(!redis || !redis->client){
			redis_ctx->err = 1;//REDIS_ERR_IO
			redis_ctx->err_str = strdup("redis server seems not exist");
			continue;
		}

		if(nts > ctx->redis_cmds.start_ts+200){
			redis_ctx->err = 8;
			redis_ctx->err_str = strdup("drop task");
			LOG_ERR("redis Task wait:%"PRIu64, nts-ctx->redis_cmds.start_ts);
			continue;
		}

		int rc = redisClusterAppendFormattedCommand((redisClusterContext*)(redis->client), redis_ctx->fmt_cmd, redis_ctx->len);
		if(rc){
			redis_ctx->err = ((redisClusterContext*)(redis->client))->err;
			redis_ctx->err_str = strdup(((redisClusterContext*)(redis->client))->errstr);
			LOG_ERR("failed to append formatted command to redis cluster client. rc:%d, errno:%d, errmsg:%s, cmd:%.*s", 
				rc, redis_ctx->err, redis_ctx->err_str, redis_ctx->len, redis_ctx->fmt_cmd);
		}
	}

	redisCLusterSendAll((redisClusterContext*)(redis->client));

	p = NULL;
	list_for_each(p, &(ctx->redis_cmds.cmds)){
		redis_ctx_t* redis_ctx = list_entry(p, redis_ctx_t, list);
		if(redis_ctx->err){
			continue;
		}

		int rc = redisClusterGetReply((redisClusterContext*)(redis->client), (void**)&(redis_ctx->reply));
		if(rc){
			redis_ctx->err = ((redisClusterContext*)(redis->client))->err;
			redis_ctx->err_str = strdup(((redisClusterContext*)(redis->client))->errstr);
			LOG_ERR("failed to get cluster reply. rc:%d, errno:%d, errmsg:%s, cmd:%.*s", 
				rc, redis_ctx->err, redis_ctx->err_str, redis_ctx->len, redis_ctx->fmt_cmd);
		}
	}

	redisClusterReset((redisClusterContext*)(redis->client));

	bool async = g_sync_call_redis? false : ctx&&ctx->co&&ctx->co->pre;
	if(!async){
		return 0;
	}

	cmd_t cmd;
	cmd.cmd = K_CMD_NOTIFY_ASYNC_REDIS_FIN;
	cmd.arg = ctx;
	if(notify_worker(worker, cmd)){
		LOG_ERR("[ALARM]FATAL!!!! failed to notify worker");
	}

	return 0;
}

static int do_redis_tw_cmd(void* arg)
{
	rpc_ctx_t* ctx = (rpc_ctx_t*)arg;
	ctx->redis_cmds.executed = 1;
	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	redis_client_t* redis = ctx->redis;
	uint64_t nts = get_monotonic_milli_second();
	prepare_redis_status(redis);

	list_head* p = NULL;
	list_for_each(p, &(ctx->redis_cmds.cmds)){
		redis_ctx_t* redis_ctx = list_entry(p, redis_ctx_t, list);
		if(!redis || !redis->client){
			redis_ctx->err = 1;//REDIS_ERR_IO
			redis_ctx->err_str = strdup("redis server seems not exist");
			continue;
		}

		if(nts > ctx->redis_cmds.start_ts+200){
			redis_ctx->err = 8;
			redis_ctx->err_str = strdup("drop task");
			LOG_ERR("redis Task wait:%"PRIu64, nts-ctx->redis_cmds.start_ts);
			continue;
		}

		int rc = redisAppendFormattedCommand((redisContext*)(redis->client), redis_ctx->fmt_cmd, redis_ctx->len);
		if(rc){
			redis_ctx->err = ((redisContext*)(redis->client))->err;
			redis_ctx->err_str = strdup(((redisContext*)(redis->client))->errstr);
			LOG_ERR("failed to append formatted command to redis tw client. rc:%d, errno:%d, errmsg:%s, cmd:%.*s", 
				rc, redis_ctx->err, redis_ctx->err_str, redis_ctx->len, redis_ctx->fmt_cmd);
		}
	}

	p = NULL;
	list_for_each(p, &(ctx->redis_cmds.cmds)){
		redis_ctx_t* redis_ctx = list_entry(p, redis_ctx_t, list);
		if(redis_ctx->err){
			continue;
		}

		int rc = redisGetReply((redisContext*)(redis->client), (void**)&(redis_ctx->reply));
		if(rc){
			redis_ctx->err = ((redisContext*)(redis->client))->err;
			redis_ctx->err_str = strdup(((redisContext*)(redis->client))->errstr);
			LOG_ERR("failed to get tw reply. rc:%d, errno:%d, errmsg:%s, cmd:%.*s", 
				rc, redis_ctx->err, redis_ctx->err_str, redis_ctx->len, redis_ctx->fmt_cmd);
		}
	}

	bool async = g_sync_call_redis? false : ctx&&ctx->co&&ctx->co->pre;
	if(!async){
		return 0;
	}

	cmd_t cmd;
	cmd.cmd = K_CMD_NOTIFY_ASYNC_REDIS_FIN;
	cmd.arg = ctx;
	if(notify_worker(worker, cmd)){
		LOG_ERR("FATAL!!!! failed to notify worker");
	}

	return 0;
}

void async_fin_redis_execute(rpc_ctx_t* ctx)
{
	LOG_DBG("fin redis execute");
	coroutine_t* co = ctx->co;
	co_resume(co);
	co_release(&co);
}

void copy_redis_client(redis_client_t* src, redis_client_t* dst)
{
	*dst = *src;
	INIT_LIST_HEAD(&(dst->replys));
	list_head* p = NULL;
	list_head* n = NULL;
	list_for_each_safe(p, n, &(src->replys)){
		list_del(p);
		redis_ctx_t* c = list_entry(p, redis_ctx_t, list);
		list_add_tail(&(c->list), &(dst->replys));
	}
}

int connect_2_redis(redis_client_t* redis, const blink::pb_config* pb_config)
{
	if(!pb_config->redis().size()){ 
		return 0;
	}

	const char* link = pb_config->redis().data();
	if(NULL == link){
		return 0;
	}

	const char* link_4_test = pb_config->redis_4_test().size()?pb_config->redis_4_test().data():NULL;
	return connect_2_real_redis(redis, link, link_4_test);
}
