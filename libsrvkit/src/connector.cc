#include <server_inner.h>

void async_conn_server(worker_thread_t* worker, proto_client_inst_t* cli)
{
	LOG_INFO("async connect to service:%s cli:%s:%d", cli->service, cli->ip, cli->port);
	async_conn_task_t* task = (async_conn_task_t*)calloc(1, sizeof(async_conn_task_t));
	INIT_LIST_HEAD(&(task->task_list));
	task->worker = worker;
	task->service = cli->service;
	strncpy(task->ip, cli->ip, sizeof(task->ip)-1);
	task->port = cli->port;
	task->fd = -1;

	server_t* server = (server_t*)worker->mt;
	size_t idx = random()%(server->num_connectors);
	async_connector_t* connector = server->async_connectors + idx;
	pthread_mutex_lock(&(connector->mutex));
	list_add_tail(&task->task_list, &connector->async_task);
	++connector->async_task_size;
	pthread_mutex_unlock(&(connector->mutex));
	sem_post(&(connector->sem_async_req));
}

void async_fin_conn_server(worker_thread_t* worker, async_conn_task_t* fin_conn)
{
	LOG_INFO("fin conn server");
	proto_client_inst_t* instance = NULL;
	size_t i = 0;
	proto_client_inst_t* inst = NULL;
	proto_client_t* client = NULL;
	std::pair<char*, int> ip_port;
	ip_port.first = fin_conn->ip;
	ip_port.second = fin_conn->port;

	client = get_clients_by_service(worker, fin_conn->service);
	if(NULL == client){
		LOG_ERR("no client for service:%s", fin_conn->service);
		goto close_fd;
	}

	for(; i < client->num_clients; ++i){
		inst = client->cli_inst_s + i;
		if(strcmp(fin_conn->ip, inst->ip) == 0 && fin_conn->port == inst->port){
			instance = inst;
			break;
		}
	}

	if(NULL == instance){
		LOG_ERR("failed to find cli instance. service:%s %s:%d", fin_conn->service, fin_conn->ip, fin_conn->port);
		goto close_fd;
	}

	if(instance->ptr){
		LOG_ERR("service:%s %s:%d has connected", fin_conn->service, fin_conn->ip, fin_conn->port);
		goto close_fd;
	}

	if(fin_conn->fd < 0){
		LOG_ERR("connect 2 service:%s %s:%d failed", fin_conn->service, fin_conn->ip, fin_conn->port);
		add_client_inst_2_wheel(worker, instance);
		goto free_task;
	}

	LOG_INFO("async reconnect ok. service::%s %s:%d", fin_conn->service, fin_conn->ip, fin_conn->port);
	MONITOR_ACC("async_connect",1);
	init_client_inst(worker, inst, ip_port, fin_conn->fd);
	goto free_task;

close_fd:
	if(fin_conn->fd > 0)
		close(fin_conn->fd);

free_task:
	free(fin_conn);
}

static void* async_connector_thread_func(void* arg)
{
	sleep(1);

	pthread_t pthd = pthread_self();
	pthread_detach(pthd);
	server_t* server = (server_t*)arg;

	async_connector_t* connector = NULL;
	for(int i = 0; i < server->num_connectors; ++i){
		async_connector_t* c = server->async_connectors + i;
		if(c->pthread_id == pthd){
			connector = c;
			break;
		}
	}

	if(NULL == connector){
		LOG_ERR("impossible here. invalid connector!!!!!!");
		return NULL;
	}

	while(!server->exit){
		sem_wait(&connector->sem_async_req);

		pthread_mutex_lock(&connector->mutex);
		list_head* p = pop_list_node(&connector->async_task);
		--connector->async_task_size;
		pthread_mutex_unlock(&connector->mutex);

		async_conn_task_t* async_task = list_entry(p, async_conn_task_t, task_list);

		LOG_INFO("recv async conn task. service:%s %s:%d", async_task->service, async_task->ip, async_task->port);
		//TODO connect
		async_task->fd = util_connect_2_svr2(async_task->ip, async_task->port); 
		if(async_task->fd<0){
			LOG_ERR("failed to connect to service:%s %s:%d", async_task->service, async_task->ip, async_task->port);
		}

		cmd_t cmd;
		cmd.cmd = K_CMD_NOTIFY_ASYNC_CONN_FIN;
		cmd.arg = async_task;
		int rc = notify_worker(async_task->worker, cmd);
		if(rc){
			LOG_ERR("failed to notify worker");
			free(async_task);
		}
	}

	return NULL;
}

void run_async_connector(server_t* server)
{
	for(int i = 0; i  < server->num_connectors; ++i){
		async_connector_t* connector = server->async_connectors+i;
		sem_init(&(connector->sem_async_req), 0, 0);
		pthread_mutex_init(&(connector->mutex), NULL);
		INIT_LIST_HEAD(&connector->async_task);

		pthread_create(&(connector->pthread_id), NULL, async_connector_thread_func, server);
	}
}
