#include "gtest/gtest.h"
#include "sched_cpu_affinity.h"

TEST(ut_cpu_sched, test)
{
	int rc = init_sched_cpu_affinity();
	if(rc){
		printf("failed to init cpu affinity info\n");
		return;
	}

	print_cpu_order();
	ASSERT_TRUE(1);
}
