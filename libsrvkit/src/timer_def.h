#ifndef __TIMER_DEF_H__
#define __TIMER_DEF_H__

#include <bim_util.h>

#define K_MAX_TIMEOUT 120
struct worker_thread_t;
struct timer_event_t;
typedef void (*fn_timer_cb)(worker_thread_t* worker, timer_event_t* event);

typedef struct timer_event_t
{
	list_head list;
	int milli_offset;
	fn_timer_cb cb;
}timer_event_t;


typedef struct time_wheel_core_t
{
	list_head* second_wheel;
	list_head milli_second_wheel[1000];
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
	time_wheel_meta_t meta;
	time_wheel_core_t time_wheel;
}time_wheel_t;

void init_timer_event(timer_event_t* tm, fn_timer_cb cb);
void init_timer(time_wheel_t* timer);
void run_timer(time_wheel_t* timer);

void add_timer_event(time_wheel_t* timer, int interval, timer_event_t* event);
void del_timer_event(time_wheel_t* timer, timer_event_t* event);

int get_next_timeout(time_wheel_t* timers);
void do_check_timer_v2(worker_thread_t* worker);

#endif//__TIMER_DEF_H__

