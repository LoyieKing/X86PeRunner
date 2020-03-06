#include"Kernel32.h"

#define UNICORN_HOOK_FUNC(func) void PreparedHook::##func##(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)

using namespace PreparedHook;


UNICORN_HOOK_FUNC(GetModuleFileNameW)
{

}


UNICORN_HOOK_FUNC(GetModuleFileNameA)
{

}

UNICORN_HOOK_FUNC(GetModuleHandleA)
{

}


UNICORN_HOOK_FUNC(GetModuleHandleExA)
{

}


UNICORN_HOOK_FUNC(GetModuleHandleExW)
{

}
UNICORN_HOOK_FUNC(GetModuleHandleW)
{

}

UNICORN_HOOK_FUNC(LoadLibraryA)
{

}
UNICORN_HOOK_FUNC(LoadLibraryExA)
{

}
UNICORN_HOOK_FUNC(LoadLibraryW)
{

}
UNICORN_HOOK_FUNC(LoadLibraryExW) 
{


}
UNICORN_HOOK_FUNC(GetProcAddress)
{

}
