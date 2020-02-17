#include "X86Emulator.h"
#include "internal.h"

X86Emulator::X86Emulator()
{
	uc_err err;

	UC_ASSERT(uc_open(UC_ARCH_X86, UC_MODE_32, &engine));
	UC_ASSERT(uc_mem_map_ptr(engine, 0x10000, 0x80000000 - 0x10000 - 0x10000, UC_PROT_ALL, (void*)0x10000));

	stack_start = malloc(STACK_SIZE);
	stack_end = (char*)stack_start + STACK_SIZE - 4;

	UC_ASSERT(uc_reg_write(engine, UC_X86_REG_ESP, &stack_end));

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
