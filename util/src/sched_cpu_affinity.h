#ifndef __SCHED_CPU_AFFINITY_H__
#define __SCHED_CPU_AFFINITY_H__

#include <list.h>
typedef struct cpu_usage_t
{
	long long unsigned usage;
	int idx;
	list_head list;
}cpu_usage_t;

typedef struct cpu_stat_t
{
	list_head cpus;
	size_t cpu_num;
	cpu_stat_t(){
		INIT_LIST_HEAD(&cpus);
		cpu_num = 0;
	}
}cpu_stat_t;

int init_sched_cpu_affinity();
void set_sched_cpu_affinity();

void print_cpu_order();

#endif//__SCHED_CPU_AFFINITY_H__

