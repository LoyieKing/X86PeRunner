#include"Emulator.h"
#include"internal.h"

void Emulator::RegWrite(int reg_id, int val)
{
	uc_err err;
	UC_ASSERT(uc_reg_write(engine, reg_id, &val));
}

int Emulator::RegRead(int reg_id)
{
	uc_err err;

	int val;
	UC_ASSERT(uc_reg_read(engine, reg_id, &val));

	return val;
}

void Emulator::Start(uint64_t begin, uint64_t until, uint64_t timeout, size_t count)
{
	uc_err err;
	UC_ASSERT(uc_emu_start(engine, begin, until, timeout, count));
}

void Emulator::Stop()
{
	uc_err err;
	UC_ASSERT(uc_emu_stop(engine));
}

Emulator::~Emulator()
{
	free(stack_start);
	uc_close(engine);
}
