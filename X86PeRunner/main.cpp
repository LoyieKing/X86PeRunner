#include<stdio.h>
#include<platform.h>
#include<capstone\capstone.h>
#include<unicorn\unicorn.h>

#include"PeLoader.h"

#include"Emulator\Emulator.h"
#include"Emulator\X86Emulator.h"

Emulator* emulator;

VOID ExecMainCallback(PE_HANDLE Pe)
{
	DWORD dwEntryPoint = PeLdrGetEntryPoint(Pe);

	
	if (Pe->IsNative)
	{
		if (Pe->IsExe)
		{
			int(*entryPoint)();
			entryPoint = (int(*)())dwEntryPoint;

			int ret = entryPoint();
		}
		else
		{
			BOOL(WINAPI *dllMain)(HINSTANCE hModule, DWORD dwReason, LPVOID);
			dllMain = (BOOL(WINAPI *)(HINSTANCE hModule, DWORD dwReason, LPVOID))dwEntryPoint;

			BOOL ret = dllMain((HMODULE)Pe->Base, DLL_PROCESS_ATTACH, NULL);
		}
	}
	else
	{
		if (Pe->IsExe)
		{
			emulator->StackPush(0x80000000);
			emulator->Start(dwEntryPoint, 0x80000000);

			int ret = emulator->RegRead(UC_X86_REG_EAX);
		}
		else
		{
			emulator->StackPush(NULL);//LPVOID
			emulator->StackPush(DLL_PROCESS_ATTACH);//DWORD dwReason
			emulator->StackPush((int)Pe->Base);//HMODULE

			emulator->StackPush(0x80000000);
			emulator->Start(dwEntryPoint, 0x80000000);

			BOOL ret = emulator->RegRead(UC_X86_REG_EAX);
		}
	}
}


FARPROC ImportCallback(PE_HANDLE Pe, PE_HANDLE NeededDll, LPCSTR ImportName, BOOL ByName)
{
	FARPROC proc = PeLdrGetProcAddressA(NeededDll, ImportName, ExecMainCallback,ImportCallback);
	if (!NeededDll->IsNative)
		return proc;

	HMODULE pe = LoadLibraryW(NeededDll->FileName);


}

int main(int argc, char* argv[])
{
	int cs_major = 0;
	int cs_minor = 0;
	cs_version(&cs_major, &cs_minor);
	printf("Capstone version:%d.%d\n", cs_major, cs_minor);

	unsigned int uc_major = 0;
	unsigned int uc_minor = 0;

	uc_version(&uc_major, &uc_minor);
	printf("Unicorn version:%d.%d\n", uc_major, uc_minor);

	if (argc < 2)
		return 0;

	emulator = new X86Emulator();

	char* peFile = argv[2];
	PE_HANDLE pe = PeLdrLoadModuleA(peFile, ExecMainCallback, ImportCallback);
	PeLdrGetEntryPoint(pe);


	return 0;
}