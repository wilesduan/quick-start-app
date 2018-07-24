#include <string.h>
#include <time.h>
#include <stdio.h>
#include "time_util.h"

const char* strtime_ymd(const long int lTime)
{
	struct tm* pTm = localtime(&lTime);
	static char szReturn[12];

	int ilen = snprintf(szReturn, sizeof(szReturn),"%d-%02d-%02d", pTm->tm_year + 1900, pTm->tm_mon+1, pTm->tm_mday);
	szReturn[ilen] = 0;

	return szReturn;
}

const char* strtime_ymdhms(const long int lTime)
{
	static char szReturn[20];
	struct tm* pTm = localtime(&lTime);
	int ilen = snprintf(szReturn, sizeof(szReturn), "%d-%02d-%02d %02d:%02d:%02d", pTm->tm_year + 1900, pTm->tm_mon + 1, pTm->tm_mday, pTm->tm_hour, pTm->tm_min, pTm->tm_sec);
	szReturn[ilen] = 0;
	return szReturn;
}

const char* strtime_ymdhms_r(const long int timestamp, char* result, size_t size)
{
	struct tm m;
	struct tm* pTm = localtime_r(&timestamp, &m);
	int ilen = snprintf(result, size-1, "%d-%02d-%02d %02d:%02d:%02d", pTm->tm_year + 1900, pTm->tm_mon + 1, pTm->tm_mday, pTm->tm_hour, pTm->tm_min, pTm->tm_sec);
	result[ilen] = 0;
	return result;
}

bool is_same_day(time_t first, time_t second)
{
	struct tm f_tm;
	struct tm s_tm;
	localtime_r(&first, &f_tm);
	localtime_r(&second, &s_tm);

	return (f_tm.tm_year == s_tm.tm_year) && (f_tm.tm_mon == s_tm.tm_mon) && (f_tm.tm_mday == s_tm.tm_mday);
}

void convert_strtime_ymd(const long int timestamp, int* year, int* month, int* day)
{
	struct tm m;
	struct tm* pTm = localtime_r(&timestamp, &m);
	if(year) *year = pTm->tm_year+1900;
	if(month) *month = pTm->tm_mon+1;
	if(day) *day = pTm->tm_mday;
}

uint64_t get_milli_second()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec*1000+tv.tv_usec/1000;
}

