#include <sched_cpu_affinity.h>

#ifndef __USE_GNU
#define __USE_GNU 
#endif

#include <sched.h>

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <util_log.h>


#define K_PRE_CPU_STAT "/tmp/.pre_stat"
#define K_CUR_CPU_STAT "/proc/stat"

static int* g_cpu_idx = NULL;
static int g_cpu_num = 0;
static int g_cur_idx = 0;
static pthread_mutex_t g_mutex_idx = PTHREAD_MUTEX_INITIALIZER;

static void read_cpu_stat(const char* stat_file, cpu_stat_t* cpu_stat)
{
	FILE* fp = fopen(stat_file, "r");
	if(!fp){
		LOG_DBG("failed to open cpu stat file:%s", stat_file);
		return;
	}

	char sz_line[102400];
	size_t n = 102400;

	char* line = sz_line;
	while(getline(&line, &n, fp) != -1){
		if(strncmp(sz_line, "cpu", 3) != 0 || strncmp(sz_line, "cpu ", 4) == 0){
			n = 102400;
			continue;
		}

		long long unsigned int cpu_idx, user,nice,sys,idle,iowait,irq,softirq; 
		sscanf(sz_line, "cpu%llu %llu %llu %llu %llu %llu %llu %llu", &cpu_idx, &user, &nice, &sys, &idle, &iowait, &irq, &softirq);
		cpu_usage_t* cpu = (cpu_usage_t*)calloc(1, sizeof(cpu_usage_t));
		INIT_LIST_HEAD(&cpu->list);
		cpu->idx = cpu_idx;
		cpu->usage = user + sys;
		++(cpu_stat->cpu_num);
		list_add_tail(&cpu->list, &cpu_stat->cpus);

		n = 102400;
	}

	fclose(fp);
}

static void save_cpu_stat()
{
	char sz_cmd[1024];
	sprintf(sz_cmd, "rm -f %s; cp %s %s", K_PRE_CPU_STAT, K_CUR_CPU_STAT, K_PRE_CPU_STAT);
	system(sz_cmd);
}

static int sort_by_idx(const void* arg1, const void* arg2)
{
	const cpu_usage_t* cpu1 = (const cpu_usage_t*)arg1;
	const cpu_usage_t* cpu2 = (const cpu_usage_t*)arg2;
	return cpu1->idx - cpu2->idx;
}

static int sort_by_usage(const void * arg1, const void* arg2)
{
	const cpu_usage_t* cpu1 = (const cpu_usage_t*)arg1;
	const cpu_usage_t* cpu2 = (const cpu_usage_t*)arg2;
	return (int)(cpu1->usage - cpu2->usage);
}

static void sort_cpu_stat(cpu_stat_t* pre_stat, cpu_stat_t* cur_stat)
{
	cpu_usage_t* pre_usages = (cpu_usage_t*)calloc(cur_stat->cpu_num, sizeof(cpu_usage_t));
	cpu_usage_t* cur_usages = (cpu_usage_t*)calloc(cur_stat->cpu_num, sizeof(cpu_usage_t));

	//prepare pre usages
	size_t i = 0;
	list_head* list = pre_stat->cpu_num == cur_stat->cpu_num?&pre_stat->cpus:&cur_stat->cpus;
	bool cp_usage = pre_stat->cpu_num == cur_stat->cpu_num;
	list_head* p = NULL;
	list_for_each(p, list){
		cpu_usage_t* c = list_entry(p, cpu_usage_t, list);
		cpu_usage_t* cpu = pre_usages + i;

		if(cp_usage)cpu->usage = c->usage;
		cpu->idx = c->idx;
		++i;
	}

	i = 0;
	list = &cur_stat->cpus;
	p = NULL;
	list_for_each(p, list){
		cpu_usage_t* c = list_entry(p, cpu_usage_t, list);
		cpu_usage_t* cpu = cur_usages + i;
		cpu->usage = c->usage;
		cpu->idx = c->idx;
		++i;
	}

	qsort(pre_usages, cur_stat->cpu_num, sizeof(cpu_usage_t), sort_by_idx);
	qsort(cur_usages, cur_stat->cpu_num, sizeof(cpu_usage_t), sort_by_idx);
	for(i = 0; i < cur_stat->cpu_num; ++i){
		cpu_usage_t* cpu1 = cur_usages + i;
		cpu_usage_t* cpu2 = pre_usages + i;
		if(cpu1->usage < cpu2->usage){
			cpu1->usage = 0;
		}else{
			cpu1->usage -= cpu2->usage;
		}
	}

	qsort(cur_usages, cur_stat->cpu_num, sizeof(cpu_usage_t), sort_by_usage);
	g_cpu_idx = (int*)calloc(cur_stat->cpu_num, sizeof(int));
	for(i = 0; i < cur_stat->cpu_num; ++i){
		cpu_usage_t* cpu = cur_usages + i;
		*(g_cpu_idx + i) = cpu->idx;
	}

	g_cpu_num = cur_stat->cpu_num;

	free(cur_usages);
	free(pre_usages);
}

static void free_cpu_stat(const cpu_stat_t* stats)
{
	list_head* p = NULL;
	list_head* next = NULL;
	list_for_each_safe(p, next, &stats->cpus){
		cpu_usage_t* cpu = list_entry(p, cpu_usage_t, list);
		free(cpu);
	}
}

int init_sched_cpu_affinity()
{
	cpu_stat_t pre_cpu_stat;
	cpu_stat_t cur_cpu_stat;

	read_cpu_stat(K_PRE_CPU_STAT, &pre_cpu_stat);
	read_cpu_stat(K_CUR_CPU_STAT, &cur_cpu_stat);
	save_cpu_stat();

	sort_cpu_stat(&pre_cpu_stat, &cur_cpu_stat);
	free_cpu_stat(&pre_cpu_stat);
	free_cpu_stat(&cur_cpu_stat);
	return 0;
}

void set_sched_cpu_affinity()
{
	if(!g_cpu_idx || !g_cpu_num){
		return;
	}

	int idx = 0;
	pthread_mutex_lock(&g_mutex_idx);
	idx = *(g_cpu_idx + (g_cur_idx++) % g_cpu_num);
	pthread_mutex_unlock(&g_mutex_idx);

	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(idx, &mask);
	int rc = sched_setaffinity(0, sizeof(mask), &mask);
	if(rc){
		LOG_ERR("failed to sched set affinity:%d", idx);
	}
}

void print_cpu_order()
{
	if(!g_cpu_idx || !g_cpu_num){
		printf("cpu sched not inited\n");
		return;
	}

	printf("CPU usage order:");
	for(int i = 0; i < g_cpu_num; ++i){
		printf("%d ", *(g_cpu_idx+i));
	}
	printf("\n");
}
