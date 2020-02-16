#include<stdio.h>
#include<platform.h>
#include<capstone\capstone.h>
#include<unicorn\unicorn.h>

int main()
{
	int cs_major = 0;
	int cs_minor = 0;
	cs_version(&cs_major, &cs_minor);
	printf("Capstone version:%d.%d\n", cs_major, cs_minor);

	unsigned int uc_major = 0;
	unsigned int uc_minor = 0;

	uc_version(&uc_major, &uc_minor);
	printf("Unicorn version:%d.%d\n", uc_major, uc_minor);

	return 0;
}