#ifndef _LIBSRVKIT_CONNECTOR_H_
#define _LIBSRVKIT_CONNECTOR_H_

typedef struct async_conn_task_t
{
	list_head task_list;
	worker_thread_t* worker;
	char* service;
	char ip[32];
	int port;
	int fd;
}async_conn_task_t;

typedef struct async_connector_t
{
	sem_t sem_async_req;
	pthread_mutex_t mutex;
	list_head async_task;
	int async_task_size;

	pthread_t pthread_id;
}async_connector_t;

#endif//_LIBSRVKIT_CONNECTOR_H_

