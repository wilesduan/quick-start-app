#ifndef __TIMER_DEF_H__
#define __TIMER_DEF_H__

#include <bim_util.h>

#define K_MAX_TIMEOUT 120
struct worker_thread_t;
typedef void (*fn_timer_cb)(worker_thread_t* worker, list_head* list);
typedef struct time_wheel_core_t
{
	list_head* second_wheel;
	list_head milli_second_wheel[1000];
	fn_timer_cb cb;
}time_wheel_core_t;

typedef struct time_wheel_meta_t
{
	uint64_t start_time;
	uint64_t last_check_time;
	size_t cur_second_idx;
	size_t cur_milli_second_idx;
	size_t max_second;
	int started;
	char bit[128];
}time_wheel_meta_t;

typedef struct time_wheel_t
{
	time_wheel_core_t req_co_timeout_wheel;
	time_wheel_core_t heartbeat_wheel;
	time_wheel_core_t idle_time_wheel;
	time_wheel_core_t disconnected_client_wheel;

	time_wheel_meta_t meta;
}time_wheel_t;

void init_timers(time_wheel_t* timers, fn_timer_cb co_timeout_cb, fn_timer_cb heartbeat_timeout_cb, 
		fn_timer_cb idle_timeout_cb, fn_timer_cb disconnect_timeout_cb);
void run_timers(time_wheel_t* timers);

void add_timeout_event_2_timer(time_wheel_t* wheel, int interval, list_head* p, int* milli_second_in_1s);
void del_timeout_event_from_timer(time_wheel_t* wheel, list_head* p);

void add_heartbeat_event_2_timer(time_wheel_t* wheel, int interval, list_head* p, int* milli_second_in_1s);
void del_heartbeat_event_from_timer(time_wheel_t* wheel, list_head* p);

void add_idle_event_2_timer(time_wheel_t* wheel, int interval, list_head* p, int* milli_second_in_1s);
void del_idle_event_from_timer(time_wheel_t* wheel, list_head* p);

void add_disconnect_event_2_timer(time_wheel_t* wheel, int interval, list_head* p, int* milli_second_in_1s);
void del_disconnect_event_from_timer(time_wheel_t* wheel, list_head* p);

int get_next_timeout(time_wheel_t* timers);
void do_check_timer_v2(worker_thread_t* worker);

#endif//__TIMER_DEF_H__

