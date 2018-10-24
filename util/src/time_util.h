#ifndef _COMMON_TIME_UTIL_H
#define _COMMON_TIME_UTIL_H

#include <stdint.h>
#include <sys/time.h>

const char* strtime_ymd(const long int);
const char* strtime_ymdhms(const long int);
const char* strtime_ymdhms_r(const long int, char* result, size_t size);
bool is_same_day(time_t first, time_t second);

void convert_strtime_ymd(const long int timestamp, int* year, int* month, int* day);
uint64_t get_milli_second();
uint64_t get_monotonic_milli_second();

#endif//_COMMON_TIME_UTIL_H

