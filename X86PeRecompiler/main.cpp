#include<stdio.h>
#include "capstone/include/capstone/capstone.h"

int main()
{
	int major = 0;
	int minor = 0;
	cs_version(&major, &minor);
	printf("Hello World!");
	return 0;
}