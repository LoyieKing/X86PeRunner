#pragma once
#include"Emulator.h"
#include<unicorn\unicorn.h>

class X86Emulator:virtual public Emulator
{
public:
	X86Emulator();

	virtual void StackPush(int val);
	virtual int StackPop();
};