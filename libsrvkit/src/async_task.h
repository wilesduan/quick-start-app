#ifndef __LIBSRVKIT_AYSNC_ROUTINE_T__
#define __LIBSRVKIT_AYSNC_ROUTINE_T__

#include <bim_util.h>

struct async_task_t;

typedef int (*fn_async_routine)(void*);
typedef struct async_task_t
{
	fn_async_routine fn_task;
	void* task_params;
	list_head list;
}async_task_t;

typedef struct async_routine_t 
{
	pthread_mutex_t mutex;
	list_head tasks; 
	size_t cnt_task;
	sem_t sem_task;

	size_t max_pending_task;

	pthread_t pthread_id;
	void* bind_data;
}async_routine_t;

async_routine_t* malloc_async_routines(int cnt, size_t max_pending_task);
int run_async_routines(async_routine_t* array, int cnt);
int add_task_2_routine(async_routine_t* routine, fn_async_routine fn, void* task_data, bool force_add = false);
#endif//__LIBSRVKIT_AYSNC_THREAD_T__

