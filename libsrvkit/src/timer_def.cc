#include <timer_def.h>
#include <server_inner.h>
#include <co_routine.h>

#define AUTO_COREDUMP  usleep(10000); *((int*)0) = 0;
static void init_time_wheel_core(time_wheel_core_t* time_wheel_core, int max_second, fn_timer_cb cb)
{
	time_wheel_core->second_wheel = (list_head*)calloc(max_second, sizeof(list_head));
	for(int i = 0; i < max_second; ++i){
		INIT_LIST_HEAD(time_wheel_core->second_wheel+i);
	}

	for(int i = 0; i < 1000; ++i){
		INIT_LIST_HEAD(time_wheel_core->milli_second_wheel+i);
	}

	time_wheel_core->cb = cb;
}

void init_timers(time_wheel_t* timers, fn_timer_cb co_timeout_cb, fn_timer_cb heartbeat_timeout_cb, 
		fn_timer_cb idle_timeout_cb, fn_timer_cb disconnect_timeout_cb)
{
	int wheel_num = K_MAX_TIMEOUT+10;
	timers->meta.start_time = get_monotonic_milli_second();
	timers->meta.last_check_time = timers->meta.start_time;
	timers->meta.cur_second_idx= 0;
	timers->meta.cur_milli_second_idx= 0;
	timers->meta.started = 0;
	timers->meta.max_second = wheel_num;
	bzero(&(timers->meta.bit), 128);

	init_time_wheel_core(&timers->req_co_timeout_wheel, wheel_num, co_timeout_cb);
	init_time_wheel_core(&timers->heartbeat_wheel, wheel_num, heartbeat_timeout_cb);
	init_time_wheel_core(&timers->idle_time_wheel, wheel_num, idle_timeout_cb);
	init_time_wheel_core(&timers->disconnected_client_wheel, wheel_num, disconnect_timeout_cb);
}

void run_timers(time_wheel_t* timers)
{
	timers->meta.start_time = get_monotonic_milli_second();
	timers->meta.last_check_time = timers->meta.start_time;
	timers->meta.cur_second_idx= 0;
	timers->meta.cur_milli_second_idx= 0;
	timers->meta.started = 1;
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

void add_timeout_event_2_timer(time_wheel_t* wheel, int interval, list_head* p, int* milli_second_in_1s)
{
	//LOG_DBG("add timeout event. interval:%d, node:%llu, fire time:%llu", interval, (unsigned long long)(p), get_monotonic_milli_second()+interval);
	list_del(p);
	INIT_LIST_HEAD(p);

	list_head* list = get_time_wheel_list(&(wheel->meta), &(wheel->req_co_timeout_wheel), interval, milli_second_in_1s);
	if(!list)return;
	list_add(p, list);
}

static void check_milli_offset(time_wheel_t* wheel, size_t milli_offset)
{
	if(!is_bit_set(wheel->meta.bit, milli_offset) || wheel->meta.cur_milli_second_idx >= milli_offset || milli_offset >= 1000){
		return;
	}
	
	list_head* list1 = wheel->req_co_timeout_wheel.milli_second_wheel+milli_offset;
	list_head* list2 = wheel->heartbeat_wheel.milli_second_wheel+milli_offset;
	list_head* list3 = wheel->idle_time_wheel.milli_second_wheel+milli_offset;
	list_head* list4 = wheel->disconnected_client_wheel.milli_second_wheel+milli_offset;
	if(list_empty(list1) && list_empty(list2) && list_empty(list3) && list_empty(list4)){
		unset_bit(wheel->meta.bit, milli_offset);
	}
}

void del_timeout_event_from_timer(time_wheel_t* wheel, list_head* p)
{
	list_del(p);
	INIT_LIST_HEAD(p);

	coroutine_t* co = list_entry(p, coroutine_t, req_co_timeout_wheel);
	size_t milli_offset = co->req_co_milli_offset;
	check_milli_offset(wheel, milli_offset);
}

void add_heartbeat_event_2_timer(time_wheel_t* wheel, int interval, list_head* p, int* milli_second_in_1s)
{
	list_del(p);
	INIT_LIST_HEAD(p);
	//LOG_DBG("add heartbeat event. interval:%d, node:%llu, fire time:%llu", interval, (unsigned long long)(p), get_monotonic_milli_second()+interval);
	list_head* list = get_time_wheel_list(&(wheel->meta), &(wheel->heartbeat_wheel), interval, milli_second_in_1s);
	if(!list)return;
	list_add(p, list);
}

void del_heartbeat_event_from_timer(time_wheel_t* wheel, list_head* p)
{
	list_del(p);
	INIT_LIST_HEAD(p);

	ev_ptr_t* ptr = list_entry(p, ev_ptr_t, heartbeat_wheel);
	size_t milli_offset = ptr->heartbeat_milli_offset;
	check_milli_offset(wheel, milli_offset);
}

void add_idle_event_2_timer(time_wheel_t* wheel, int interval, list_head* p, int* milli_second_in_1s)
{
	list_del(p);
	INIT_LIST_HEAD(p);
	list_head* list = get_time_wheel_list(&(wheel->meta), &(wheel->idle_time_wheel), interval, milli_second_in_1s);
	if(!list)return;
	list_add(p, list);

	//LOG_DBG("add idle event. interval:%d, node:%llu, fire time:%llu, offset:%", interval, (unsigned long long)(p), get_monotonic_milli_second()+interval);
}

void del_idle_event_from_timer(time_wheel_t* wheel, list_head* p)
{
	list_del(p);
	INIT_LIST_HEAD(p);

	ev_ptr_t* ptr = list_entry(p, ev_ptr_t, idle_time_wheel);
	size_t milli_offset = ptr->idle_milli_offset;
	check_milli_offset(wheel, milli_offset);
}

void add_disconnect_event_2_timer(time_wheel_t* wheel, int interval, list_head* p, int* milli_second_in_1s)
{
	//LOG_DBG("add disconnect event. interval:%d, node:%llu, fire time:%llu", interval, (unsigned long long)(p), get_monotonic_milli_second()+interval);
	list_del(p);
	INIT_LIST_HEAD(p);
	list_head* list = get_time_wheel_list(&(wheel->meta), &(wheel->disconnected_client_wheel), interval, milli_second_in_1s);
	if(!list)return;
	list_add(p, list);
}

void del_disconnect_event_from_timer(time_wheel_t* wheel, list_head* p)
{
	list_del(p);
	INIT_LIST_HEAD(p);

	proto_client_inst_t* cli  = list_entry(p, proto_client_inst_t, disconnected_client_wheel);
	size_t milli_offset = cli->disconnect_milli_offset;
	check_milli_offset(wheel, milli_offset);
}

void scatter_wheel(time_wheel_t* timers)
{
	size_t idx = (timers->meta.cur_second_idx+1)%(timers->meta.max_second);
	timers->meta.cur_second_idx = idx;
	list_head* list;
	list_head* p;
	list_head* next;

	p = next = NULL;
	list = timers->req_co_timeout_wheel.second_wheel+idx;
	list_for_each_safe(p, next, list){
		list_del(p);
		coroutine_t* co = list_entry(p, coroutine_t, req_co_timeout_wheel);
		if(co->req_co_milli_offset>1000){
			assert(0);
			continue;
		}
		list_head* milli = timers->req_co_timeout_wheel.milli_second_wheel+co->req_co_milli_offset;
		list_add(&co->req_co_timeout_wheel, milli);
		set_bit(timers->meta.bit, co->req_co_milli_offset);
	}

	p = next = NULL;
	list = timers->heartbeat_wheel.second_wheel+idx;
	list_for_each_safe(p, next, list){
		list_del(p);
		ev_ptr_t* ptr = list_entry(p, ev_ptr_t, heartbeat_wheel);
		if(ptr->heartbeat_milli_offset > 1000){
			assert(0);
			continue;
		}
		list_head* milli = timers->heartbeat_wheel.milli_second_wheel+ptr->heartbeat_milli_offset;
		list_add(&ptr->heartbeat_wheel, milli);
		set_bit(timers->meta.bit, ptr->heartbeat_milli_offset);
	}

	p = next = NULL;
	list = timers->idle_time_wheel.second_wheel+idx;
	list_for_each_safe(p, next, list){
		list_del(p);
		ev_ptr_t* ptr = list_entry(p, ev_ptr_t, idle_time_wheel);
		if(ptr->idle_milli_offset > 1000){
			assert(0);
			continue;
		}
		list_head* milli = timers->idle_time_wheel.milli_second_wheel+ptr->idle_milli_offset;
		list_add(&ptr->idle_time_wheel, milli);
		set_bit(timers->meta.bit, ptr->idle_milli_offset);
	}

	p = next = NULL;
	list = timers->disconnected_client_wheel.second_wheel+idx;
	list_for_each_safe(p, next, list){
		list_del(p);
		proto_client_inst_t* cli  = list_entry(p, proto_client_inst_t, disconnected_client_wheel);
		if(cli->disconnect_milli_offset > 1000){
			assert(0);
			continue;
		}
		list_head* milli = timers->disconnected_client_wheel.milli_second_wheel+cli->disconnect_milli_offset;
		list_add(&cli->disconnected_client_wheel, milli);
		set_bit(timers->meta.bit, cli->disconnect_milli_offset);
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

int get_next_timeout(time_wheel_t* timers)
{
	int next = get_next_nonzero_offset(timers->meta.bit, timers->meta.cur_milli_second_idx, 1000);
	uint64_t now = get_monotonic_milli_second();
	if(now > timers->meta.last_check_time + next){
		return 0;
	}

	return next+timers->meta.last_check_time-now;
}

void do_check_timer_v2(worker_thread_t* worker)
{
	uint64_t now = get_monotonic_milli_second();
	time_wheel_t* timers = &worker->timers;
	if(now < timers->meta.last_check_time && now + 1000 > timers->meta.last_check_time){
		return;
	}

	//修改系统时间导致
	if(now + 1000 < timers->meta.last_check_time || now > timers->meta.last_check_time+timers->meta.max_second*1000){
		LOG_ERR("###FATAL#### change start time.last_check_time:%llu, now:%llu", timers->meta.last_check_time, now);
		AUTO_COREDUMP;
		return;
	}

	int i = timers->meta.cur_milli_second_idx;
	uint64_t milli = timers->meta.last_check_time;

	list_head* list;
	list_head* p;
	list_head* next;

loop:
	for(; i < 1000 && milli<=now; ++i,++milli){
		timers->meta.cur_milli_second_idx = i;
		if(!is_bit_set(timers->meta.bit, i)){
			continue;
		}

		LOG_DBG("idx:%d, now:%llu, last_check:%llu, milli_second_in_1s:%d, check:%llu", timers->meta.cur_milli_second_idx, now, timers->meta.last_check_time, i, milli);
		list = timers->req_co_timeout_wheel.milli_second_wheel+i;
		p = NULL;
		next = NULL;
		list_for_each_safe(p, next, list){
			LOG_ERR("fire timeout event. now:%llu node:%llu, milli:%d, second:%d", now, (unsigned long long)p, i, timers->meta.cur_second_idx);
			list_del(p);
			INIT_LIST_HEAD(p);
			(timers->req_co_timeout_wheel.cb)(worker, p);
		}

		list = timers->heartbeat_wheel.milli_second_wheel + i;
		p = next = NULL;
		list_for_each_safe(p, next, list){
			LOG_DBG("fire hearbeat event. now:%llu node:%llu", now, (unsigned long long)p);
			list_del(p);
			INIT_LIST_HEAD(p);
			(timers->heartbeat_wheel.cb)(worker, p);
		}

		list = timers->idle_time_wheel.milli_second_wheel + i;
		p = next = NULL;
		list_for_each_safe(p, next, list){
			LOG_ERR("fire idle event. now:%llu node:%llu, milli:%d, second:%d", now, (unsigned long long)p, i, timers->meta.cur_second_idx);
			list_del(p);
			INIT_LIST_HEAD(p);
			(timers->idle_time_wheel.cb)(worker, p);
		}

		list = timers->disconnected_client_wheel.milli_second_wheel + i;
		p = next = NULL;
		list_for_each_safe(p, next, list){
			LOG_DBG("fire disconnect event. now:%llu node:%llu", now, (unsigned long long)p);
			list_del(p);
			INIT_LIST_HEAD(p);
			(timers->disconnected_client_wheel.cb)(worker, p);
		}

		unset_bit(timers->meta.bit, i);
	}

	if(i == 1000 && milli <= now){
		LOG_DBG("scatter");
		scatter_wheel(timers);
		i = 0;
		goto loop;
	}

	timers->meta.last_check_time = now;
	LOG_DBG("end:%d, now:%llu, last_check:%llu", timers->meta.cur_milli_second_idx, now, timers->meta.last_check_time);
}

