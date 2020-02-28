#pragma once

#include<unicorn\unicorn.h>

#include"PeLoader.h"

struct ImportHookData
{
	PE_HANDLE Dll;
	LPCSTR ImportName;
	BOOL ByName;
	FARPROC Proc;
	uc_hook* Hook;
};

void	ExecMainCallback	(PE_HANDLE Pe);
FARPROC ImportCallback		(PE_HANDLE Pe, PE_HANDLE NeededDll, LPCSTR ImportName, BOOL ByName);
void	UnicornHookCallback	(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);