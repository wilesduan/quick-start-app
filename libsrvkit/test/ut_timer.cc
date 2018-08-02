#include <timer_def.h>
#include "server_inner.h"
#include <time.h>
#include <stdlib.h>

#define K_ADD_INTERVAL 1010

list_head free_co_list;
worker_thread_t worker;

coroutine_t* get_co()
{
	if(!(list_empty(&free_co_list))){
		list_head* p = pop_list_node(&free_co_list);
		return list_entry(p, coroutine_t, req_co_timeout_wheel);
	}

	coroutine_t* co = (coroutine_t*)calloc(1, sizeof(coroutine_t));
	INIT_LIST_HEAD(&co->req_co_timeout_wheel);
	return co;
}

void recycle_co(list_head* p)
{
	list_del(p);
	list_add(p, &free_co_list);
}

static void fn_timeout_cb(worker_thread_t* worker, list_head* p)
{
	uint64_t now = get_milli_second();
	coroutine_t* co = list_entry(p, coroutine_t, req_co_timeout_wheel);
	if(now > co->session_code + 3 || co->session_code -3 > now){
		assert(0);
	}
	printf("cur:%llu, milli_in_1s:%u, cmdid:%llu\n", now, co->req_co_milli_offset, co->hash_key);
	recycle_co(&co->req_co_timeout_wheel);
}

static void fn_heartbeat_cb(worker_thread_t* worker, list_head* p)
{
}

static void fn_idle_cb(worker_thread_t* worker, list_head* p)
{
}

static void fn_disconn_cb(worker_thread_t* worker, list_head* p)
{
}


int main()
{
	srandom(time(NULL));

	uint64_t i = 0;
	INIT_LIST_HEAD(&free_co_list);
	init_timers(&worker.timers, fn_timeout_cb, fn_heartbeat_cb, fn_idle_cb, fn_disconn_cb);
	coroutine_t* co = get_co();
	co->hash_key = ++i;
	int interval = random()%30+10;
	co->session_code = get_milli_second() + interval;
	add_timeout_event_2_timer(&worker.timers, interval, &co->req_co_timeout_wheel, &co->req_co_milli_offset);
	run_timers(&worker.timers);
	uint64_t last = get_milli_second();

	int wait = get_next_timeout(&worker.timers);
	while(1){
		usleep(wait*1000);

		uint64_t now = get_milli_second();
		printf("wait time:%d\n", wait);

		co = get_co();
		co->hash_key = ++i;
		interval = random()%30+10;
		co->session_code = now + interval;
		add_timeout_event_2_timer(&worker.timers, interval, &co->req_co_timeout_wheel, &co->req_co_milli_offset);
#if 0
		if(wait >= K_ADD_INTERVAL-1 || now >= last + K_ADD_INTERVAL-1){
			printf("########wait:%d, now:%llu >= last:%llu + 10\n", wait, now, last);
			co = get_co();
			co->hash_key = ++i;
			co->session_code = now + K_ADD_INTERVAL;
			add_timeout_event_2_timer(&worker.timers, K_ADD_INTERVAL, &co->req_co_timeout_wheel, &co->req_co_milli_offset);
			last = now;
		}
#endif

		do_check_timer_v2(&worker);
		wait = get_next_timeout(&worker.timers);
	}

	return 0;
}
