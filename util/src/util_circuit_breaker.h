#ifndef __UTIL_CIRCUIT_BREAKER_H_
#define __UTIL_CIRCUIT_BREAKER_H_

#include <time.h>

typedef struct circuit_breaker_tick_t
{
	int succ;
	int failed;
	//time_t ts;
}circuit_breaker_tick_t;

enum circuit_breaker_state
{
	EN_CIRCUIT_BREAKER_CLOSED = 1,
	EN_CIRCUIT_BREAKER_OPEN = 2,
	EN_CIRCUIT_BREAKER_HALF_OPEN = 3,
};

typedef struct circuit_breaker_t
{
	/**state change strategy;**/
	int window_size;
	int failure_threshold;
	int half_open_ratio;
	//float failure_ratio;
	
	/**statistic**/
	time_t last_ts;
	int failure;
	int success;
	int total_access;

	/**state store**/
	circuit_breaker_state state;
	int window_start;
	time_t window_ts;
	int last_tick;
	int num_ticks;
	circuit_breaker_tick_t* ticks;

}circuit_breaker_t;

circuit_breaker_t* malloc_circuit_breaker(int window_size, int failure_threshold, int half_open_ratio, int ticks = 60);
void free_circuit_breaker(circuit_breaker_t* breaker);
bool check_in_circuit_breaker(circuit_breaker_t* breaker);
void succ_circuit_breaker(circuit_breaker_t* breaker);
void fail_circuit_breaker(circuit_breaker_t* breaker);
int get_breaker_state(circuit_breaker_t* breaker);
#endif//__UTIL_CIRCUIT_BREAKER_H_

