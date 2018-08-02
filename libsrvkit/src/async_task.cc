#include <async_task.h>

extern int  g_svr_exit; 

async_routine_t* malloc_async_routines(int cnt, size_t max_pending_task)
{
	async_routine_t* routines = (async_routine_t*)calloc(cnt, sizeof(async_routine_t));
	if(NULL == routines){
		LOG_ERR("Out of memory");
		return NULL;
	}

	for(int i = 0; i < cnt; ++i){
		async_routine_t* routine = routines + i;

		pthread_mutex_init(&(routine->mutex), NULL);
		INIT_LIST_HEAD(&(routine->tasks));
		sem_init(&(routine->sem_task), 0, 0); 
		routine->max_pending_task = max_pending_task;
	}

	return routines;
}

static void recycle_task(async_task_t* task)
{
	free(task);
}

static void* async_pthread_routine(void* arg)
{
	async_routine_t* routine = (async_routine_t*)arg;
	pthread_detach(routine->pthread_id);
	//struct timespec abs_timeout = {1, 0};
	while(!g_svr_exit){
		//if(sem_timedwait(&(routine->sem_task), &abs_timeout)){
		if(sem_wait(&(routine->sem_task))){
			printf("wait##\n");
			continue;
		}

		pthread_mutex_lock(&(routine->mutex));
		list_head* p = pop_list_node(&(routine->tasks));
		--routine->cnt_task;
		pthread_mutex_unlock(&(routine->mutex));
		if(!p){
			LOG_ERR("inpossible here!");
			continue;
		}

		async_task_t* task = list_entry(p, async_task_t, list);
		if(!task->fn_task){
			LOG_ERR("[ALARM]miss task fn!!! BE CARE MEM LEAK");
		}else{
			(task->fn_task)(task->task_params);
		}

		recycle_task(task);
	}

	LOG_INFO("server exited");
	return NULL;
}

int run_async_routines(async_routine_t* array, int cnt)
{
	for(int i = 0; i < cnt; ++i){
		async_routine_t* routine = array + i;
		pthread_create(&(routine->pthread_id), NULL, async_pthread_routine, routine);
	}
	return 0;
}

int add_task_2_routine(async_routine_t* routine, fn_async_routine fn, void* task_data, bool force_add)
{
	if(!force_add && routine->cnt_task > routine->max_pending_task){
		LOG_ERR("too much pending task. %llu:%llu", routine->cnt_task, routine->max_pending_task);
		return -1;
	}

	async_task_t* task = (async_task_t*)calloc(1, sizeof(async_task_t));
	if(NULL == task){
		LOG_ERR("OUT OF MEM");
		return -2;
	}

	task->fn_task = fn;
	task->task_params = task_data;
	INIT_LIST_HEAD(&(task->list));

	pthread_mutex_lock(&(routine->mutex));
	++routine->cnt_task;
	list_add_tail(&(task->list), &(routine->tasks));
	pthread_mutex_unlock(&(routine->mutex));

	sem_post(&(routine->sem_task));
	return 0;
}

