#include "StdcallCallConverter.h"

typedef int (FAR WINAPI *CallFunc)(int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int);

StdcallCallConverter::StdcallCallConverter()
{

}


void StdcallCallConverter::Call(Emulator * emulator, ImportHookData * data)
{
	int* x86sp = (int*)emulator->RegRead(UC_X86_REG_ESP);
	CallFunc func = (CallFunc)data->Proc;

	//x86sp[0]: PC that will return to	
	int ret = func(x86sp[1], x86sp[2], x86sp[3], x86sp[4], x86sp[5], x86sp[6], x86sp[7], x86sp[8], x86sp[9], x86sp[10], x86sp[11], x86sp[12], x86sp[13], x86sp[14], x86sp[15], x86sp[16], x86sp[17], x86sp[18], x86sp[19], x86sp[20]);

	emulator->RegWrite(UC_X86_REG_EAX, ret);
}

StdcallCallConverter::~StdcallCallConverter()
{
}
