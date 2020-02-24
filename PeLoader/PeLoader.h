#pragma once

#include<Windows.h>
/*
* Yet Another Code Translator (c) mamaich, 2011
*
* PE file loader public functions
*
* All functions are unicode. In case of error they call SetLastError()
*
*/
#ifdef __cplusplus
extern "C" {
#endif

#ifndef PE_EXPORT
#define PE_EXPORT
#endif


	typedef struct PeFile
	{
		DWORD Signature;		// 'FILE'
		HANDLE hFile; 			// File handle
		LPCWSTR FileName;
		BOOL IsNative;			// TRUE if native DLL, in this case hFile, AllocatedMem, etc are not used
		BOOL IsExe;				// This file is EXE, not a DLL
		BOOL IsStub;			// This DLL is a stub DLL (filename ends with .86.dll)
		BOOL IsGUI;				// True == file is GUI, false == console. Only valid if IsExe==true
		BOOL AllocatedMem;  	// Memory for image (Base) was allocated by us
		void *Base;				// Loaded image base (0 if not loaded yet)
		DWORD Size;				// Module size
		void *Data;				// Can be any thing
	} *PE_HANDLE;

	typedef FARPROC(*IMPORT_CALLBACK)(PE_HANDLE Pe, PE_HANDLE NeededDll, LPCSTR ImportName, BOOL ByName);
	typedef VOID(*EXEC_MAIN_CALLBACK)(PE_HANDLE Pe);


	PE_EXPORT DWORD PeLdrCalcModuleRamSize(PE_HANDLE);
	PE_EXPORT BOOL PeLdrFixupModule(PE_HANDLE Pe);
	PE_EXPORT BOOL PeLdrProcessModuleImports(PE_HANDLE Pe, EXEC_MAIN_CALLBACK ExecMainCallback, IMPORT_CALLBACK ImportCallback);
	//PE_EXPORT int PeLdrStartProgram(LPWSTR ExePath);

	typedef struct PeFile *PE_HANDLE;

	PE_EXPORT PE_HANDLE PeLdrLoadModule(LPCWSTR FileName,EXEC_MAIN_CALLBACK ExecMainCallback, IMPORT_CALLBACK ImportCallback);
	PE_EXPORT PE_HANDLE PeLdrLoadModuleA(LPCSTR FileName, EXEC_MAIN_CALLBACK ExecMainCallback, IMPORT_CALLBACK ImportCallback);
	PE_EXPORT PE_HANDLE PeLdrFindModule(LPCWSTR FileName);
	PE_EXPORT PE_HANDLE PeLdrFindModuleA(LPCSTR FileName);
	PE_EXPORT PE_HANDLE PeLdrFindModuleByBase(DWORD Base);
	PE_EXPORT void PeLdrCloseAllModules();
	PE_EXPORT DWORD PeLdrGetPageSize();
	PE_EXPORT DWORD PeLdrGetEntryPoint(PE_HANDLE Pe);
	PE_EXPORT DWORD PeLdrGetModuleBase(PE_HANDLE Pe);
	PE_EXPORT DWORD PeLdrGetModuleFileNameA(PE_HANDLE Pe, LPSTR FileName, DWORD Size);
	PE_EXPORT DWORD PeLdrGetModuleFileName(PE_HANDLE Pe, LPWSTR FileName, DWORD Size);
	PE_EXPORT DWORD PeLdrGetFixedLoadAddress(PE_HANDLE Pe);
	PE_EXPORT FARPROC PeLdrGetProcAddressA(PE_HANDLE Dll, LPCSTR Name, EXEC_MAIN_CALLBACK ExecMainCallback, IMPORT_CALLBACK ImportCallback);
	PE_EXPORT FARPROC PeLdrGetProcAddress(PE_HANDLE Dll, LPCWSTR Name, EXEC_MAIN_CALLBACK ExecMainCallback, IMPORT_CALLBACK ImportCallback);
	PE_EXPORT LPSTR PeLdrGetSystemDirectoryA();
	PE_EXPORT LPWSTR PeLdrGetSystemDirectoryW();
	PE_EXPORT int PeLdrIsValidX86(LPCWSTR ExePath);	// return 0 = not valid, 1 = GUI, -1 = console

#ifdef __cplusplus
}
#endif

