#pragma once
#include<unicorn\unicorn.h>

class Emulator
{
public:

	virtual void StackPush(int val) = 0;
	virtual int StackPop() = 0;
	virtual void RegWrite(int reg_id, int val);
	virtual int RegRead(int reg_id);

	virtual void Start(uint64_t begin, uint64_t until, uint64_t timeout = 0, size_t count = 0);
	virtual void Stop();

	uc_engine* engine;

	~Emulator();
protected:

	void* stack_start;
	void* stack_end;
};