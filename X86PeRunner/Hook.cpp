#include"Hook.h"

#include"Emulator\Emulator.h"
#include"Emulator\X86Emulator.h"

#include"CallConverter\StdcallCallConverter.h"
#include"CallConverter\CallConverter.h"
#include<map>

Emulator* emulator = new X86Emulator;
CallConverter* callConverter = new StdcallCallConverter;

void ExecMainCallback(PE_HANDLE Pe)
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
	/*
	PE_HANDLE Pe		:	需要指定导入函数的PE文件，例如被打开的exe。Pe一定是运行在Unicorn模拟器上的。
	PE_HANDLE NeededDll	:	指定要被导入的PE(Dll)文件。
	NeededDll如果是非Native（需要运行在Unicorn模拟器上）的，则直接返回导入地址，全部交给模拟器内的PE文件们处理；
	如果是Native的，则hook导入地址，在运行到导入地址时停止并Native调用函数（注意需要修复函数调用问题）
	LPCSTR ImportName	:	被导入的函数名，也可能是序号
	BOOL ByName			:	为true则ImportName是一个char*，为false则ImportName实则一个整形序号（PE规定）
	*/

	FARPROC proc;
	if (NeededDll->IsNative)
	{
		proc = GetProcAddress((HMODULE)NeededDll->Base, ImportName);
		if (proc == NULL)
		{
			printf("Hook fail!Master dll:%s\tSlave dll:%s\tImportName:%s\n", Pe->FileName, NeededDll->FileName, ImportName);
		}
		std::map<LPCSTR, ImportHookData*> *hooks;
		if (NeededDll->Data == nullptr)
		{
			hooks = new std::map<LPCSTR, ImportHookData*>();
			NeededDll->Data = hooks;
		}
		else
		{
			hooks = (std::map<LPCSTR, ImportHookData*>*)NeededDll->Data;
		}

		if (hooks->find(ImportName) == hooks->end())
		{
			uc_hook* hh = new uc_hook;

			auto data = new ImportHookData;
			data->Dll = NeededDll;
			data->ImportName = ImportName;
			data->ByName = ByName;
			data->Proc = proc;
			data->Hook = hh;

			void UnicornHookCallback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
			uc_hook_add(emulator->engine, hh, UC_HOOK_CODE, UnicornHookCallback, (void*)data, (uint64_t)proc, (uint64_t)proc);

			hooks->insert(std::make_pair(ImportName, data));
		}

	}
	else
	{
		proc = PeLdrGetProcAddressA(NeededDll, ImportName, ExecMainCallback, ImportCallback);
	}

	return proc;

}

void UnicornHookCallback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	ImportHookData* data = (ImportHookData*)user_data;

	callConverter->Call(emulator, data);

	int pc = emulator->StackPop();
	emulator->RegWrite(UC_X86_REG_EIP, pc);
}