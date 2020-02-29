#include "X86Emulator.h"
#include "internal.h"
#include <string.h>

#include "capstone\capstone.h"

csh cs_handle;


void UnicornHookAllCallback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	cs_insn* ins;
	cs_disasm(cs_handle, (uint8_t*)address, size, address, 1, &ins);
	char* mnemonic = ins->mnemonic + 8;

	char* op_str = ins->op_str + 8;

	printf("0x%08llx:%s %s\n", address, mnemonic, op_str);
	if (strcmp(mnemonic, "ret") == 0)
	{
		static int reti = 0;
		reti++;
	}
	cs_free(ins, 1);
}


X86Emulator::X86Emulator()
{
	uc_err err;

	UC_ASSERT(uc_open(UC_ARCH_X86, UC_MODE_32, &engine));
	UC_ASSERT(uc_mem_map_ptr(engine, 0x10000, 0x80000000 - 0x10000 - 0x10000, UC_PROT_ALL, (void*)0x10000));

	uc_hook hh;
	UC_ASSERT(uc_hook_add(engine, &hh, UC_HOOK_CODE, UnicornHookAllCallback, NULL, 0x10000, 0x80000000 - 0x10000 - 0x10000));

	stack_start = malloc(STACK_SIZE);
	stack_end = (char*)stack_start + STACK_SIZE - 4;

	UC_ASSERT(uc_reg_write(engine, UC_X86_REG_ESP, &stack_end));

	cs_opt_mem opt_mem;
	opt_mem.calloc = calloc;
	opt_mem.free = free;
	opt_mem.malloc = malloc;
	opt_mem.realloc = realloc;
	opt_mem.vsnprintf = vsnprintf;
	cs_option(cs_handle, CS_OPT_MEM, (size_t)&opt_mem);


	cs_err cserr;
	cserr = cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle);

}

void X86Emulator::StackPush(int val)
{
	uc_err err;

	int* esp;
	UC_ASSERT(uc_reg_read(engine, UC_X86_REG_ESP, &esp));
	esp--;
	UC_ASSERT(uc_reg_write(engine, UC_X86_REG_ESP, &esp));
	*esp = val;
}

int X86Emulator::StackPop()
{
	uc_err err;

	int ret;
	int* esp;
	UC_ASSERT(uc_reg_read(engine, UC_X86_REG_ESP, &esp));
	ret = *esp;
	esp++;
	UC_ASSERT(uc_reg_write(engine, UC_X86_REG_ESP, &esp));

	return ret;
}
