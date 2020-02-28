#include<stdio.h>
#include"PeLoader.h"
#include"Hook.h"


int main(int argc, char* argv[])
{
	if (argc < 2)
		return 0;

	char* peFile = argv[1];
	PE_HANDLE pe = PeLdrLoadModuleA(peFile, ExecMainCallback, ImportCallback);
	//PeLdrGetEntryPoint(pe);


	return 0;
}