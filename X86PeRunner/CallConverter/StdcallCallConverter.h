#pragma once

#include"CallConverter.h"

class StdcallCallConverter:public CallConverter
{
public:
	StdcallCallConverter();

	virtual void Call(Emulator* emulator, ImportHookData* data);

	~StdcallCallConverter();
private:
};