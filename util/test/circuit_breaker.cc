#include <gtest/gtest.h>
#include "util_circuit_breaker.h"
#include <mockcpp/mockcpp.hpp>
#include <unistd.h>
#include <stdlib.h>

#include <string>

time_t now;

time_t mock_time(time_t *seconds)
{
	return *seconds = now;
}

TEST(ut_circuit_breaker, check_state)
{
	time(&now);

	MOCKER(time)
		.stubs()
		.will(invoke(mock_time));

	circuit_breaker_t* breaker = malloc_circuit_breaker(10, 100, 10, 60);

	//CASE 1: check init state (EXPECT CLOSED)
	ASSERT_EQ(get_breaker_state(breaker), 1);

	//CASE 2: 9s failed 50 (EXPECT CLOSED)
	for(int k = 0; k < 9; ++k){
		for(int i = 0; i < 5; ++i){
			fail_circuit_breaker(breaker);
		}
		++now;
	}
	ASSERT_EQ(get_breaker_state(breaker), 1);
	printf("[xxxxx]breaker failure:%d, total_access:%d\n", breaker->failure, breaker->total_access);

	//CASE 3: 9s failed 100 (EXPECT OPEN)
	for(int i = 0; i < 100; ++i){
		fail_circuit_breaker(breaker);
	}
	//sleep(1);
	check_in_circuit_breaker(breaker);
	printf("[xxxxx]breaker failure:%d, total_access:%d\n", breaker->failure, breaker->total_access);
	ASSERT_EQ(get_breaker_state(breaker), 2);

	//CASE 4: then sleep 10s (EXPECT HALF_OPEN)
	now += 11;
	check_in_circuit_breaker(breaker);
	ASSERT_EQ(get_breaker_state(breaker), 3);

	//CASE 5: failed 20 (EXPECT OPEN)
	for(int k = 0; k < 5; ++k){
		++now;
		for(int i = 0; i < 4; ++i){
			fail_circuit_breaker(breaker);
		}
	}
	ASSERT_EQ(get_breaker_state(breaker), 2);
	printf("[xxxxx]breaker failure:%d, total_access:%d\n", breaker->failure, breaker->total_access);

	//CASE 6: sleep 10s (EXPECT HALF_OPEN)
	now += 11;
	check_in_circuit_breaker(breaker);
	ASSERT_EQ(get_breaker_state(breaker), 3);

	//CASE 7: succ 100 (EXPECT CLOSED)
	for(int k = 0; k < 7; ++k){
		++now;
		for(int i = 0; i < 10; ++i){
			succ_circuit_breaker(breaker);
		}
	}
	ASSERT_EQ(get_breaker_state(breaker), 1);
	printf("[xxxxx]breaker failure:%d, total_access:%d\n", breaker->failure, breaker->total_access);

	srandom(1);
	for(int i =0; i < 10000; ++i){
		if(!check_in_circuit_breaker(breaker)){
			printf("[xxxxx]breaker failure:%d, total_access:%d\n", breaker->failure, breaker->total_access);
			++now;
			continue;
		}

		if(get_breaker_state(breaker) == 3){
			succ_circuit_breaker(breaker);
			continue;
		}

		if(random() % 2){
			succ_circuit_breaker(breaker);
		}else{
			fail_circuit_breaker(breaker);
		}
	}

	free_circuit_breaker(breaker);

	GlobalMockObject::verify();
}
