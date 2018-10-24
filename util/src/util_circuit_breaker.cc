#include <util_circuit_breaker.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <util_log.h>

circuit_breaker_t* malloc_circuit_breaker(int window_size, int failure_threshold, int half_open_ratio, int ticks)
{
	if(window_size > ticks){
		ticks = window_size+1;
	}

	circuit_breaker_tick_t* breaker_ticks = (circuit_breaker_tick_t*)calloc(ticks, sizeof(circuit_breaker_tick_t));
	if(!breaker_ticks){
		return NULL;
	}

	circuit_breaker_t* breaker = (circuit_breaker_t*)calloc(1, sizeof(circuit_breaker_t));
	if(!breaker){
		free(breaker_ticks);
		return NULL;
	}

	breaker->window_size = window_size;
	breaker->failure_threshold = failure_threshold;
	breaker->half_open_ratio = half_open_ratio;

	time(&breaker->last_ts);
	breaker->window_ts = breaker->last_ts;
	breaker->last_tick = 0;

	breaker->state = EN_CIRCUIT_BREAKER_CLOSED;
	breaker->num_ticks = ticks;
	breaker->ticks = breaker_ticks;
	return breaker;
}

void free_circuit_breaker(circuit_breaker_t* breaker)
{
	if(!breaker){
		return;
	}

	if(breaker->ticks){
		free(breaker->ticks);
	}

	free(breaker);
}

static void reset_circuit_breaker(circuit_breaker_t* breaker, time_t now)
{
	memset(breaker->ticks, 0, sizeof(circuit_breaker_tick_t)*breaker->num_ticks);
	breaker->failure = breaker->success = breaker->total_access = 0;
	breaker->state = EN_CIRCUIT_BREAKER_CLOSED;
	breaker->window_start = 0;
	breaker->window_ts = now;
	breaker->last_ts = now;
	breaker->last_tick = 0;
}

static void change_breaker_state(circuit_breaker_t* breaker, time_t now, circuit_breaker_state state)
{
	reset_circuit_breaker(breaker, now);
	breaker->state = state;
}

static circuit_breaker_tick_t* switch_circuit_breaker_state(circuit_breaker_t* breaker)
{
	time_t now;
	time(&now);
	LOG_DBG("BEFORE SWITCH. now:%llu strategy:%d:%d:%d state:%d:%d:%d:%d data:%llu:%d:%d", now, breaker->window_size, breaker->failure_threshold, breaker->half_open_ratio, breaker->state, breaker->window_start, breaker->last_tick, breaker->num_ticks, breaker->last_ts, breaker->failure, breaker->total_access);
	if(now < breaker->window_ts){
		LOG_ERR("time roll back. %llu:%llu", now, breaker->window_ts);
		reset_circuit_breaker(breaker, now);
	}

	int interval = now - breaker->window_ts;
	while(interval >= breaker->window_size){
		if(interval >= 3*breaker->window_size || interval >= breaker->num_ticks){
			reset_circuit_breaker(breaker,now);
			break;
		}

		int advance = interval-breaker->window_size+1;
		int idx = breaker->window_start;
		for(int i = 0; i < advance; ++i){
			idx = (breaker->window_start+i)%(breaker->num_ticks);
			circuit_breaker_tick_t* tick = breaker->ticks + idx;
			breaker->total_access -= (tick->succ+tick->failed);
			breaker->failure -= tick->failed;
			breaker->success -= tick->succ;
			memset(tick, 0, sizeof(circuit_breaker_tick_t));
		}

		breaker->window_start = (breaker->window_start+advance)%(breaker->num_ticks);
		breaker->window_ts += advance;
		break;
	}

	if(breaker->state == EN_CIRCUIT_BREAKER_OPEN && now - breaker->last_ts <= breaker->window_size){
		LOG_DBG("IN OPEN STATE %llu:%llu", now,  breaker->last_ts);
		return breaker->ticks+breaker->last_tick;
	}

	breaker->last_ts = now;
	breaker->last_tick = (breaker->window_start + (now-breaker->window_ts))%(breaker->num_ticks);
	switch(breaker->state){
		case EN_CIRCUIT_BREAKER_CLOSED:
			if(breaker->failure >= breaker->failure_threshold){
				LOG_INFO("####change state from CLOSED to OPEN\n");
				//breaker->state = EN_CIRCUIT_BREAKER_OPEN;
				change_breaker_state(breaker, now, EN_CIRCUIT_BREAKER_OPEN);
			}
			break;
		case EN_CIRCUIT_BREAKER_HALF_OPEN:
			{
				LOG_DBG("IN HALF OPEN. strategy:%d:%d:%d state:%d:%d:%d:%d data:%llu:%d:%d", breaker->window_size, breaker->failure_threshold, breaker->half_open_ratio, breaker->state, breaker->window_start, breaker->last_tick, breaker->num_ticks, breaker->last_ts, breaker->failure, breaker->total_access);
				if(breaker->failure > 5){
					//breaker->state = EN_CIRCUIT_BREAKER_OPEN;
					change_breaker_state(breaker, now, EN_CIRCUIT_BREAKER_OPEN);
					LOG_INFO("####change state from HALF OPEN to OPEN\n");
				}else if(breaker->success > 10){
					LOG_INFO("####change state from HALF OPEN to CLOSED\n");
					//breaker->state = EN_CIRCUIT_BREAKER_CLOSED;
					//reset_circuit_breaker(breaker,now);
					change_breaker_state(breaker, now, EN_CIRCUIT_BREAKER_CLOSED);
				}
			}
			break;
		case EN_CIRCUIT_BREAKER_OPEN:
			{
				LOG_DBG("IN BREAKER OPEN. strategy:%d:%d:%d state:%d:%d:%d:%d data:%llu:%d:%d", breaker->window_size, breaker->failure_threshold, breaker->half_open_ratio, breaker->state, breaker->window_start, breaker->last_tick, breaker->num_ticks, breaker->last_ts, breaker->failure, breaker->total_access);
				//breaker->state = EN_CIRCUIT_BREAKER_HALF_OPEN;
				change_breaker_state(breaker, now, EN_CIRCUIT_BREAKER_HALF_OPEN);
			}
		default:
			break;
	}

	LOG_DBG("AFTER SWITCH. strategy:%d:%d:%d state:%d:%d:%d:%d data:%llu:%d:%d", breaker->window_size, breaker->failure_threshold, breaker->half_open_ratio, breaker->state, breaker->window_start, breaker->last_tick, breaker->num_ticks, breaker->last_ts, breaker->failure, breaker->total_access);
	return breaker->ticks+breaker->last_tick;
}

bool check_in_circuit_breaker(circuit_breaker_t* breaker)
{
	if(!breaker){
		return true;
	}

	switch_circuit_breaker_state(breaker);
	switch(breaker->state){
		case EN_CIRCUIT_BREAKER_CLOSED:
		case EN_CIRCUIT_BREAKER_HALF_OPEN:
			return true;
		case EN_CIRCUIT_BREAKER_OPEN:
			return false;
		default:
			break;
	}

	return true;
}

void succ_circuit_breaker(circuit_breaker_t* breaker)
{
	if(!breaker){
		return;
	}

	circuit_breaker_tick_t* tick = switch_circuit_breaker_state(breaker);
	++tick->succ;
	++breaker->total_access;
	++breaker->success;
	LOG_DBG("succ breaker. strategy:%d:%d:%d state:%d:%d:%d:%d data:%llu:%d:%d", breaker->window_size, breaker->failure_threshold, breaker->half_open_ratio, breaker->state, breaker->window_start, breaker->last_tick, breaker->num_ticks, breaker->last_ts, breaker->failure, breaker->total_access);
}

void fail_circuit_breaker(circuit_breaker_t* breaker)
{
	if(!breaker){
		return; 
	}

	circuit_breaker_tick_t* tick = switch_circuit_breaker_state(breaker);
	++tick->failed;
	++breaker->total_access;
	++breaker->failure;
	LOG_DBG("fail breaker. strategy:%d:%d:%d state:%d:%d:%d:%d data:%llu:%d:%d", breaker->window_size, breaker->failure_threshold, breaker->half_open_ratio, breaker->state, breaker->window_start, breaker->last_tick, breaker->num_ticks, breaker->last_ts, breaker->failure, breaker->total_access);
}

int get_breaker_state(circuit_breaker_t* breaker)
{
	return breaker->state;
}
