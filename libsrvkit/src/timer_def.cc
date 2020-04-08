#include <timer_def.h>
#include <server_inner.h>
#include <co_routine.h>
#include <strings.h>

#define AUTO_COREDUMP  usleep(10000); *((int*)0) = 0;

void init_timer_event(timer_event_t* tm, fn_timer_cb cb)
{
	if(!tm){
		return;
	}

	bzero(tm ,sizeof(timer_event_t));
	INIT_LIST_HEAD(&tm->list);
	tm->cb = cb;
}

static void init_time_wheel_core(time_wheel_core_t* time_wheel_core, int max_second)
{
	time_wheel_core->second_wheel = (list_head*)calloc(max_second, sizeof(list_head));
	for(int i = 0; i < max_second; ++i){
		INIT_LIST_HEAD(time_wheel_core->second_wheel + i);
	}

	for(int i = 0; i < 1000; ++i){
		INIT_LIST_HEAD(time_wheel_core->milli_second_wheel+i);
	}
}

void init_timer(time_wheel_t* timer)
{
	int wheel_num = K_MAX_TIMEOUT+10;
	timer->meta.start_time = get_monotonic_milli_second();
	timer->meta.last_check_time = timer->meta.start_time;
	timer->meta.cur_second_idx= 0;
	timer->meta.cur_milli_second_idx= 0;
	timer->meta.started = 0;
	timer->meta.max_second = wheel_num;
	bzero(&(timer->meta.bit), 128);

	init_time_wheel_core(&timer->time_wheel, wheel_num);
}

void run_timer(time_wheel_t* timer)
{
	timer->meta.start_time = get_monotonic_milli_second();
	timer->meta.last_check_time = timer->meta.start_time;
	timer->meta.cur_second_idx= 0;
	timer->meta.cur_milli_second_idx= 0;
	timer->meta.started = 1;
}

static void set_bit(char* bit, int milli_offset)
{
	char  mask = 1<<(milli_offset%8);
	int offset = milli_offset/8;
	bit[offset] = bit[offset] | mask;
}

static void unset_bit(char* bit, int milli_offset)
{
	char  mask = 1<<(milli_offset%8);
	int offset = milli_offset/8;
	bit[offset] = bit[offset] & (~mask);
}

static bool is_bit_set(char* bit, int milli_offset)
{
	char mask = 1<<(milli_offset%8);
	int offset = milli_offset/8;
	return bit[offset] & mask;
}

static list_head* get_time_wheel_list(time_wheel_meta_t* meta, time_wheel_core_t* wheel, int interval, int* milli_second_in_1s)
{
	uint64_t now = get_monotonic_milli_second();

	//修改系统时间导致
	if(now + 1000 < meta->last_check_time || now > meta->last_check_time+meta->max_second*1000){
		LOG_ERR("###FATAL#### change start time.last_check_time:%llu, now:%llu", meta->last_check_time, now);
		AUTO_COREDUMP;
		return NULL;
	}

	if(now < meta->last_check_time){
		interval += (meta->last_check_time-now);
	}

	if(interval <= 0) interval = 1;

	uint64_t offset = meta->started?(now-meta->start_time+interval):interval;
	int milli_offset = offset%1000;
	int second_offset = offset/1000;

	if(milli_second_in_1s){
		*milli_second_in_1s = milli_offset;
	}

	size_t second_idx = second_offset%(meta->max_second);
	LOG_DBG("start:%llu, now:%llu, fire time:%llu interval:%d, milli_offset:%d, second_offset:%d, second idx:%llu, cur idx:%llu", meta->start_time, now, now+interval, interval, milli_offset, second_offset, second_idx, meta->cur_second_idx);
	if((interval/1000) && (second_idx == meta->cur_second_idx)){
            LOG_ERR("###FATAL### if get this log, something get wrong, check cur second idx:%llu and start time:%llu, second_idx:%llu, now:%llu, offset:%llu, interval:%d, max_second:%llu, milli_offset:%llu, second_offset:%llu", meta->cur_second_idx, meta->start_time, second_idx, now, offset, interval, meta->max_second, milli_offset, second_offset);
            second_idx = (meta->cur_second_idx+ second_offset)%(meta->max_second);
	}

	if(second_idx != meta->cur_second_idx){
		return wheel->second_wheel + second_idx;
	}

	set_bit(meta->bit, milli_offset);
	return wheel->milli_second_wheel + milli_offset;
}

static void check_milli_offset(time_wheel_t* wheel, size_t milli_offset)
{
	if(!is_bit_set(wheel->meta.bit, milli_offset) || wheel->meta.cur_milli_second_idx >= milli_offset || milli_offset >= 1000){
		return;
	}
	
	list_head* list = wheel->time_wheel.milli_second_wheel+milli_offset;
	if(list_empty(list)){ 
		unset_bit(wheel->meta.bit, milli_offset);
	}
}

void add_timer_event(time_wheel_t* timer, int interval, timer_event_t* event)
{
	if(!timer || !interval || !event){
		return;
	}

	list_del(&event->list);
	INIT_LIST_HEAD(&event->list);
	list_head* list = get_time_wheel_list(&(timer->meta), &(timer->time_wheel), interval, &event->milli_offset);
	if(!list) return;
	list_add(&event->list, list);
}

void del_timer_event(time_wheel_t* timer, timer_event_t* event)
{
	list_del(&event->list);
	INIT_LIST_HEAD(&event->list);

	size_t milli_offset = event->milli_offset;
	check_milli_offset(timer, milli_offset);
}

void scatter_wheel(time_wheel_t* timer)
{
	size_t idx = (timer->meta.cur_second_idx+1)%(timer->meta.max_second);
	timer->meta.cur_second_idx = idx;
	list_head* list;
	list_head* p;
	list_head* next;

	p = next = NULL;
	list = timer->time_wheel.second_wheel+idx;
	list_for_each_safe(p, next, list){
		list_del(p);
		timer_event_t* event = list_entry(p, timer_event_t, list);
		if(event->milli_offset>1000){
			assert(0);
			continue;
		}
		list_head* milli = timer->time_wheel.milli_second_wheel+event->milli_offset;
		list_add(&event->list, milli);
		set_bit(timer->meta.bit, event->milli_offset);
	}
}

static int lowest_bit(uint64_t i)
{
	uint32_t high = i>>32;
	uint32_t low = i & 0xFFFFFFFF;
	uint16_t s_h = low?low>>16:high>>16;
	uint16_t s_l = low?low&0xFFFF:high&0xFFFF;
	int offset = low?0:32;
	int idx = 0;
	if(s_l){
		while((!(s_l & 1<<idx)) && idx<16){
			++idx;
		}
	}else{
		offset += 16;
		while((!(s_h & 1<<idx)) && idx<16){
			++idx;
		}
	}

	return offset+idx;
}

int get_next_nonzero_offset(char* bit, int offset, int end = 1000)
{
	int idx = offset>>6;
	uint64_t* start = (uint64_t*)bit;
	uint64_t* p = start+idx;

loop:
	if(((p-start)<<6) > end){
		return end-offset;
	}

	if(*p){
		return ((p-start)<<6)+lowest_bit(*p)-offset;
	}else{
		++p;
		goto loop;
	}
}

int get_next_timeout(time_wheel_t* timer)
{
	int next = get_next_nonzero_offset(timer->meta.bit, timer->meta.cur_milli_second_idx, 1000);
	uint64_t now = get_monotonic_milli_second();
	if(now > timer->meta.last_check_time + next){
		return 0;
	}

	return next+timer->meta.last_check_time-now;
}

void do_check_timer_v2(worker_thread_t* worker)
{
	uint64_t now = get_monotonic_milli_second();
	time_wheel_t* timer = &worker->timer;
	if(now < timer->meta.last_check_time && now + 1000 > timer->meta.last_check_time){
		return;
	}

	//修改系统时间导致
	if(now + 1000 < timer->meta.last_check_time || now > timer->meta.last_check_time+timer->meta.max_second*1000){
		LOG_ERR("###FATAL#### change start time.last_check_time:%llu, now:%llu", timer->meta.last_check_time, now);
		AUTO_COREDUMP;
		return;
	}

	int i = timer->meta.cur_milli_second_idx;
	uint64_t milli = timer->meta.last_check_time;

	list_head* list;
	list_head* p;
	list_head* next;

loop:
	for(; i < 1000 && milli<=now; ++i,++milli){
		timer->meta.cur_milli_second_idx = i;
		if(!is_bit_set(timer->meta.bit, i)){
			continue;
		}

		LOG_DBG("idx:%d, now:%llu, last_check:%llu, milli_second_in_1s:%d, check:%llu", timer->meta.cur_milli_second_idx, now, timer->meta.last_check_time, i, milli);
		list = timer->time_wheel.milli_second_wheel+i;
		p = NULL;
		next = NULL;
		list_for_each_safe(p, next, list){
			LOG_ERR("fire timeout event. now:%llu node:%llu, milli:%d, second:%d", now, (unsigned long long)p, i, timer->meta.cur_second_idx);
			list_del(p);
			INIT_LIST_HEAD(p);
			timer_event_t* event = list_entry(p, timer_event_t, list);
			(event->cb)(worker, event);
		}

		unset_bit(timer->meta.bit, i);
	}

	if(i == 1000 && milli <= now){
		LOG_DBG("scatter");
		scatter_wheel(timer);
		i = 0;
		goto loop;
	}

	LOG_DBG("end:%d, now:%llu, last_check:%llu", timer->meta.cur_milli_second_idx, now, timer->meta.last_check_time);
	timer->meta.last_check_time = now;
}

