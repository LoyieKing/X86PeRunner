// Modules can be loaded dynamically, but dynamic unload is not supported for simplicity (we don't keep usage count).
// PeLdrCloseModule should be called for all modules at the same time - during process exit (or not called at all).
// DllMain/TLS callbacks are called with DLL_PROCESS_DETACH only in PeLdrCloseModule
//


#include "PeLoader.h"
#include <stdlib.h>
#include <assert.h>
#include "classes.h"
#include <stdio.h>
#include <ImageHlp.h>

#pragma  warning( disable: 4996 )
#define LogInfo LogErr
#define LogWarn LogErr

static void LogErr(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);

	char chInput[512];
	vsprintf(chInput, fmt, va);
	OutputDebugStringA(chInput);
}

static LPCRITICAL_SECTION PeInitLdrCs()
{
	LPCRITICAL_SECTION CS = new CRITICAL_SECTION;
	InitializeCriticalSection(CS);
	return CS;
}

static LPCRITICAL_SECTION CSPeLdr = PeInitLdrCs();

#define MAX_MODULES 256
static bool HasExe = false;	// Used to track the EXE file
static int ModulesCount = 0;
static PE_HANDLE Modules[MAX_MODULES];


LPWSTR PeLdrGetSystemDirectoryW()
{
	static wchar_t System32[1024];
	if (System32[0] == 0)
	{
		GetModuleFileNameW(0, System32, 1024);
		wchar_t *P = wcsrchr(System32, '\\');
		if (P)
			*P = 0;
		wcscat_s<1024>(System32, L"\\System32");
	}
	return System32;
}

LPSTR PeLdrGetSystemDirectoryA()
{
	static char System32[1024];
	if (System32[0] == 0)
	{
		GetModuleFileNameA(0, System32, 1024);
		char *P = strrchr(System32, '\\');
		if (P)
			*P = 0;
		strcat_s<1024>(System32, "\\System32");
	}
	return System32;
}

// allocate a buffer via malloc() and fill it with the full path 
static wchar_t *PeLdrGetFullPathName(const wchar_t* FileName)
{
	DWORD Need = GetFullPathName(FileName, 0, 0, 0);
	wchar_t *Ret = (wchar_t*)malloc(Need * 2 + 2);
	if (GetFullPathName(FileName, Need + 1, Ret, 0))
		return Ret;
	else
		return _wcsdup(FileName);
}

// Check given handle and set last error
static BOOL PeLdrIsValidHandle(PE_HANDLE Pe)
{
	__try
	{
		if (Pe == 0 || memcmp(&Pe->Signature, "FILE", 4) != 0)
		{
			SetLastError(ERROR_INVALID_HANDLE);
			return FALSE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	return TRUE;
}

// search for stub DLL before app DLL
static DWORD PeLdrSearchPath(
	__in          LPCWSTR lpPath,
	__in          LPCWSTR lpFileName,
	__in          LPCWSTR lpExtension,
	__in          DWORD nBufferLength,
	__out         LPWSTR lpBuffer,
	__out         LPWSTR* lpFilePart
)
{
	wchar_t MyPath[1024];
	wchar_t MyFName[1024];

	// first search exe dir, then current dir, then hardcoded system dir, then the specified path
	PE_HANDLE Exe = PeLdrFindModule(0);
	MyPath[0] = 0;
	if (Exe)
	{
		wcscpy_s<1024>(MyPath, Exe->FileName);
		wchar_t *Tmp = wcsrchr(MyPath, '\\');
		if (Tmp)
		{
			*Tmp = 0;
			wcscat_s<1024>(MyPath, L";");
		}
	}
	GetCurrentDirectory(1024, MyFName);
	wcscat_s<1024>(MyPath, MyFName);
	wcscat_s<1024>(MyPath, L";");
	wcscat_s<1024>(MyPath, PeLdrGetSystemDirectoryW());
	if (lpPath)
	{
		wcscat_s<1024>(MyPath, L";");
		wcscat_s<1024>(MyPath, lpPath);
	}
	lpPath = MyPath;

	// first search for stub DLL that may overload the application DLL
	wcscpy_s<1024>(MyFName, lpFileName);
	wchar_t *DllName = wcsrchr(MyFName, '\\');
	if (DllName == 0)
		DllName = MyFName - 1;
	DllName++;
	wchar_t *DllExt = wcsrchr(DllName, '.');
	if (DllExt)
		*DllExt = 0;
	wcscat(DllName, L".86.dll");	// possible buffer overflow!
	DWORD Tmp = SearchPath(lpPath, DllName, lpExtension, nBufferLength, lpBuffer, lpFilePart);
	if (Tmp)
		return Tmp;

	return SearchPath(lpPath, lpFileName, lpExtension, nBufferLength, lpBuffer, lpFilePart);
}

// Alloc memory and open file or return existing handle if file already loaded
static PE_HANDLE PeLdrOpenModuleNoAdd(LPCWSTR FileName)
{
	char Buff1[512];
	BOOL IsStub = FALSE;

	CLock L(&CSPeLdr); L.Lock();

	if (ModulesCount >= MAX_MODULES - 1)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return 0;
	}

	wchar_t Buff[1024];
	if (PeLdrSearchPath(0, FileName, L".DLL", 1024, Buff, 0) == 0)
		wcscpy_s<1024>(Buff, FileName);

	if (wcslen(Buff)>9)
	{
		if (_wcsicmp(Buff + wcslen(Buff) - 7, L".86.dll") == 0)
			IsStub = TRUE;
		if (wcslen(FileName)>7)
		{
			if (_wcsicmp(FileName + wcslen(FileName) - 7, L".86.dll") == 0)
				IsStub = FALSE;	// input file name was already ".86.dll", so don't stubify it ourselves
		}
	}

	HANDLE H = CreateFileW(Buff, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (H == INVALID_HANDLE_VALUE)
	{
		LogErr("PeLdr can't open file: %S\n", Buff);
		SetLastError(ERROR_NOT_FOUND);
		return NULL;
	}

	// Validate PE
	DWORD Len = 0;
	if (ReadFile(H, Buff1, 512, &Len, 0) == FALSE || Len != 512 || Buff1[0] != 'M' || Buff1[1] != 'Z')
	{
		LogErr("PeLdr invalid file format (no MZ): %S\n", Buff);
		CloseHandle(H);
		SetLastError(ERROR_INVALID_EXE_SIGNATURE);
		return 0;
	}
	if (SetFilePointer(H, ((PIMAGE_DOS_HEADER)Buff1)->e_lfanew, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		LogErr("PeLdr invalid file format (bad e_lfanew): %S (%d)\n", Buff, GetLastError());
		CloseHandle(H);
		SetLastError(ERROR_INVALID_EXE_SIGNATURE);
		return 0;
	}
	if (ReadFile(H, Buff1, 512, &Len, 0) == FALSE || Len != 512 || Buff1[0] != 'P' || Buff1[1] != 'E' || Buff1[2] != 0 || Buff1[3] != 0)
	{
		LogErr("PeLdr invalid file format (no PE): %S\n", Buff);
		CloseHandle(H);
		SetLastError(ERROR_INVALID_EXE_SIGNATURE);
		return 0;
	}
	if (Buff1[4] != 0x4c || Buff1[5] != 1)
	{
		LogErr("PeLdr invalid machine (not 0x14c): %S\n", Buff);
		CloseHandle(H);
		SetLastError(ERROR_INVALID_EXE_SIGNATURE);
		return 0;
	}
	bool ThisIsExe = !(IMAGE_FILE_DLL&(((IMAGE_FILE_HEADER*)(4 + Buff1))->Characteristics));

	SetFilePointer(H, 0, 0, FILE_BEGIN);

	PE_HANDLE Pe = (struct PeFile*)malloc(sizeof(struct PeFile));
	if (Pe == 0)
	{
		CloseHandle(H);
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return 0;
	}

	memset(Pe, 0, sizeof(struct PeFile));
	memcpy(&Pe->Signature, "FILE", 4);

	Pe->IsGUI = ((PIMAGE_NT_HEADERS)Buff1)->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI;

	Pe->hFile = H;
	Pe->FileName = PeLdrGetFullPathName(Buff);
	//	if(IsStub)
	//		wcscpy_s((wchar_t*)Pe->FileName+wcslen(Pe->FileName)-7,10,L".dll");	// remove ".86.dll" from the end
	//Pe->PeLdrTlsIndex = TLS_OUT_OF_INDEXES;	// not using TLS
	//Pe->ModuleTlsIndex = -1;	// not using TLS
	Pe->IsNative = FALSE;
	Pe->IsStub = IsStub;

	Len = wcslen(FileName);
	if (Len<4)
		return Pe;

	if (ThisIsExe)
		Pe->IsExe = TRUE;
#if 0
	if (towlower(FileName[Len - 1]) == 'e' && towlower(FileName[Len - 2]) == 'x' && towlower(FileName[Len - 3]) == 'e' &&
		FileName[Len - 4] == '.')
		Pe->IsExe = TRUE;		// assume that one EXE file never loads another EXE by LoadLibrary. Todo: check for IMAGE_FILE_DLL
	if (towlower(FileName[Len - 1]) == 'm' && towlower(FileName[Len - 2]) == 'o' && towlower(FileName[Len - 3]) == 'c' &&
		FileName[Len - 4] == '.')
		Pe->IsExe = TRUE;		// .COM file
#endif
	return Pe;
}

static PE_HANDLE PeLdrOpenModule(LPCWSTR FileName)
{
	PE_HANDLE Pe = PeLdrOpenModuleNoAdd(FileName);
	if (Pe)
	{
		CLock L(&CSPeLdr); L.Lock();
		if (ModulesCount<MAX_MODULES - 1)
			Modules[InterlockedIncrement((volatile LONG*)&ModulesCount) - 1] = Pe;
		if (Pe->IsExe)
		{
			if (HasExe)
				Pe->IsExe = FALSE;		// Only the first loaded file that is not IMAGE_FILE_DLL => our EXE
			else
				HasExe = true;
		}
	}
	return Pe;
}

// Close handles and free memory
static BOOL PeLdrCloseModule(PE_HANDLE Pe)
{
	// TODO: remove this PE from module list!
	CLock L(&CSPeLdr); L.Lock();

	if (!PeLdrIsValidHandle(Pe))
		return FALSE;

	//PeLdrNotifyNewThread(Pe, DLL_PROCESS_DETACH);

	HANDLE H = Pe->hFile;
	Pe->hFile = INVALID_HANDLE_VALUE;
	free((void*)Pe->FileName);

	if (Pe->AllocatedMem)
	{
		Pe->AllocatedMem = FALSE;
		VirtualFree(Pe->Base, Pe->Size, MEM_RELEASE);
	}

	BOOL IsNative = Pe->IsNative;
	free(Pe);
	if (!IsNative)
		return CloseHandle(H);
	return TRUE;
}

// Closes all modules
PE_EXPORT void PeLdrCloseAllModules()
{
	CLock L(&CSPeLdr); L.Lock();
	while (ModulesCount>0)
		PeLdrCloseModule(Modules[InterlockedDecrement((volatile LONG*)&ModulesCount)]);
}

// Return page size
PE_EXPORT DWORD PeLdrGetPageSize()
{
	static DWORD PageSize = 0;
	SYSTEM_INFO Si;
	if (PageSize)
		return PageSize;
	GetSystemInfo(&Si);
	PageSize = Si.dwPageSize;
	return PageSize;
}

// Calculate needed virtual memory size for the whole module, including all needed headers,
// section alignment, etc. ImageSize value in PE may be incorrect.
PE_EXPORT DWORD PeLdrCalcModuleRamSize(PE_HANDLE Pe)
{
	if (Pe->IsNative)
		return 0;

	CLock L(&CSPeLdr); L.Lock();

	DWORD LastVA = 0;

	HANDLE HM = CreateFileMapping(Pe->hFile, 0, PAGE_READONLY, 0, 0, 0);
	if (HM == 0)
		return 0;
	void *Base = MapViewOfFile(HM, FILE_MAP_READ, 0, 0, 0);
	if (Base == 0)
	{
		DWORD Tmp = GetLastError();
		CloseHandle(HM);
		SetLastError(Tmp);
		return 0;
	}

	IMAGE_NT_HEADERS *NT = ImageNtHeader(Base);

	if (NT->Signature != IMAGE_NT_SIGNATURE)
	{
		SetLastError(ERROR_IMAGE_MACHINE_TYPE_MISMATCH);
		NT = 0;
	}

	if (NT == 0)
	{
		DWORD Tmp = GetLastError();
		UnmapViewOfFile(Base);
		CloseHandle(HM);
		SetLastError(Tmp);
		return 0;
	}

	IMAGE_SECTION_HEADER *Sec = (IMAGE_SECTION_HEADER*)(sizeof(IMAGE_NT_HEADERS) + (char*)NT);

	for (int i = 0; i<NT->FileHeader.NumberOfSections; i++)
	{
		DWORD SectionEnd = Sec[i].VirtualAddress + max(Sec[i].Misc.VirtualSize, Sec[i].SizeOfRawData);
		if (LastVA<SectionEnd)
			LastVA = SectionEnd;
	}

	LastVA += PeLdrGetPageSize() - 1;
	LastVA = (LastVA / PeLdrGetPageSize())*PeLdrGetPageSize();

	UnmapViewOfFile(Base);
	CloseHandle(HM);
	return LastVA;
}



PE_EXPORT DWORD PeLdrGetModuleFileNameA(PE_HANDLE Pe, LPSTR FileName, DWORD Size)
{
	if (FileName == 0 || Size == 0)
		return 0;
	if (!PeLdrIsValidHandle(Pe))
		return 0;
	SetLastError(0);
	if (wcslen(Pe->FileName) + 1 >= Size)
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
	WideCharToMultiByte(CP_ACP, 0, Pe->FileName, -1, FileName, Size, 0, 0);
	FileName[Size - 1] = 0;
	return min(wcslen(Pe->FileName), Size);
}

PE_EXPORT DWORD PeLdrGetModuleFileName(PE_HANDLE Pe, LPWSTR FileName, DWORD Size)
{
	if (FileName == 0 || Size == 0)
		return 0;
	if (!PeLdrIsValidHandle(Pe))
		return 0;
	if (wcslen(Pe->FileName) + 1 >= Size)
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
	SetLastError(0);
	wcsncpy(FileName, Pe->FileName, Size);
	return min(wcslen(Pe->FileName) + 1, Size);
}

// returns the desired load address if relocs are stripped or 0 if relocs are present
PE_EXPORT DWORD PeLdrGetFixedLoadAddress(PE_HANDLE Pe)
{
	if (Pe->IsNative)
		return 0;

	CLock L(&CSPeLdr); L.Lock();

	DWORD ImgBase = 0;

	HANDLE HM = CreateFileMapping(Pe->hFile, 0, PAGE_READONLY, 0, 0, 0);
	if (HM == 0)
		return 0;
	void *Base = MapViewOfFile(HM, FILE_MAP_READ, 0, 0, 0);
	if (Base == 0)
	{
		DWORD Tmp = GetLastError();
		CloseHandle(HM);
		SetLastError(Tmp);
		return 0;
	}

	IMAGE_NT_HEADERS *NT = ImageNtHeader(Base);

	if (NT->Signature != IMAGE_NT_SIGNATURE)
	{
		SetLastError(ERROR_IMAGE_MACHINE_TYPE_MISMATCH);
		NT = 0;
	}

	if (NT == 0)
	{
		DWORD Tmp = GetLastError();
		UnmapViewOfFile(Base);
		CloseHandle(HM);
		SetLastError(Tmp);
		return 0;
	}

	// Assume that EXE files compiled for OS <5.0 may contain incorrect relocs (true for HEROESW.EXE from HOMM 1)
	if ((NT->FileHeader.Characteristics&IMAGE_FILE_RELOCS_STRIPPED) || (Pe->IsExe && NT->OptionalHeader.MajorOperatingSystemVersion<5))
		ImgBase = NT->OptionalHeader.ImageBase;

	UnmapViewOfFile(Base);
	CloseHandle(HM);
	return ImgBase;
}

// Load file data into memory, if DesiredAddress==0 - allocate memory, return address of loaded module
static LPVOID PeLdrInternalLoadModule(PE_HANDLE Pe, LPVOID DesiredAddress)
{
	if (Pe->IsNative)
		return 0;

	CLock L(&CSPeLdr); L.Lock();

	DWORD Tmp;
	Pe->AllocatedMem = FALSE;
	DWORD ModuleSize = PeLdrCalcModuleRamSize(Pe);

	if (ModuleSize && DesiredAddress) // as we can't rebase - try to "get" memory where needed (possibly overwriting something)
	{
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		for (DWORD i = (DWORD)DesiredAddress; i<(DWORD)DesiredAddress + ModuleSize; i += si.dwAllocationGranularity)
		{
			if (VirtualAlloc((void*)i, si.dwAllocationGranularity, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) == 0)
			{
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQuery((void*)i, &mbi, sizeof(mbi));
				if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &Tmp) == 0)	// reuse that memory
				{
					Tmp = GetLastError();
					LogInfo("Reusing address: %08X, base address: %08X failed, error=%d\n", i, mbi.BaseAddress, Tmp);
				}
				else
				{
					LogInfo("Reusing address: %08X, base address: %08X, size %08X\n", i, mbi.BaseAddress, mbi.RegionSize);
					i += mbi.RegionSize - si.dwAllocationGranularity;
				}
			}
		}
	}

	if (ModuleSize && DesiredAddress == 0)
	{
		DesiredAddress = (LPVOID)PeLdrGetFixedLoadAddress(Pe);	// Get base address if fixed
		DesiredAddress = VirtualAlloc(DesiredAddress, ModuleSize, MEM_COMMIT, PAGE_READWRITE);
		if (DesiredAddress)
			Pe->AllocatedMem = TRUE;
	}
	if (DesiredAddress == 0 || ModuleSize == 0)
	{
		goto Error;
	}

	VirtualProtect(DesiredAddress, ModuleSize, PAGE_READWRITE, &Tmp);

	Pe->Base = DesiredAddress;
	Pe->Size = ModuleSize;
	memset(DesiredAddress, 0, ModuleSize);
	char *Base = (char*)DesiredAddress;

	LogWarn("%08X-%08X : %S\n", Pe->Base, (DWORD)Pe->Base + ModuleSize, Pe->FileName);

	IMAGE_DOS_HEADER *Dos = (IMAGE_DOS_HEADER*)Base;
	SetFilePointer(Pe->hFile, 0, 0, SEEK_SET);
	//	if(!ReadFile(Pe->hFile,Dos,sizeof(IMAGE_DOS_HEADER),&Tmp,0))
	if (!ReadFile(Pe->hFile, Dos, PeLdrGetPageSize(), &Tmp, 0))	// Heroes 3 WOG stores its data just after PE before 1 section
		goto Error;

	IMAGE_NT_HEADERS *NT = (IMAGE_NT_HEADERS*)(Base + Dos->e_lfanew);
	SetFilePointer(Pe->hFile, Dos->e_lfanew, 0, SEEK_SET);
	if (!ReadFile(Pe->hFile, NT, sizeof(IMAGE_NT_HEADERS), &Tmp, 0))
		goto Error;

	if (Dos->e_magic != IMAGE_DOS_SIGNATURE || NT->Signature != IMAGE_NT_SIGNATURE || NT->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		SetLastError(ERROR_IMAGE_MACHINE_TYPE_MISMATCH);
		goto Error;
	}

	IMAGE_SECTION_HEADER *Sec = (IMAGE_SECTION_HEADER*)(sizeof(IMAGE_NT_HEADERS) + (char*)NT);

	if (!ReadFile(Pe->hFile, Sec, sizeof(IMAGE_SECTION_HEADER)*NT->FileHeader.NumberOfSections, &Tmp, 0))
		goto Error;

	for (int i = 0; i<NT->FileHeader.NumberOfSections; i++)
	{
		SetFilePointer(Pe->hFile, Sec[i].PointerToRawData, 0, SEEK_SET);
		if (Sec[i].VirtualAddress == 0)
			continue;
		if (Sec[i].PointerToRawData == 0 && Sec[i].Misc.VirtualSize == 0)	// Some strange files have this for BSS, and nonzero PhysSize
			continue;
		if (!ReadFile(Pe->hFile, Base + Sec[i].VirtualAddress, Sec[i].SizeOfRawData, &Tmp, 0))
			goto Error;
	}

	if (!PeLdrFixupModule(Pe))
		goto Error;

	if (!PeLdrProcessModuleImports(Pe))
		goto Error;

	//PeLdrNotifyNewThread(Pe, DLL_PROCESS_ATTACH);

	return Base;

Error:
	Tmp = GetLastError();
	if (Pe->AllocatedMem)
	{
		Pe->AllocatedMem = FALSE;
		VirtualFree(Pe->Base, ModuleSize, MEM_RELEASE);
	}
	SetLastError(Tmp);
	return 0;
}

// Process fixups
PE_EXPORT BOOL PeLdrFixupModule(PE_HANDLE Pe)
{
	if (Pe->IsNative)
		return 0;

	CLock L(&CSPeLdr); L.Lock();

	DWORD Tmp;
	if (Pe->Base == 0)
	{
		SetLastError(ERROR_INVALID_HANDLE_STATE);
		return FALSE;
	}

	IMAGE_NT_HEADERS *NT = ImageNtHeader(Pe->Base);
	IMAGE_BASE_RELOCATION *Reloc = (IMAGE_BASE_RELOCATION*)ImageDirectoryEntryToData(Pe->Base, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &Tmp);

	if (Reloc == 0)		// Module does not have relocations
		return TRUE;

	DWORD PrevReloc = 0;
	while (Reloc->VirtualAddress)
	{
		WORD *Fixup = (WORD*)(sizeof(IMAGE_BASE_RELOCATION) + (char*)Reloc);
		for (DWORD i = 0; i<(Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2; i++)
		{
			int RelType = ((Fixup[i] & 0xF000) >> 12);
			if (RelType == IMAGE_REL_BASED_HIGHLOW)
			{
				*(DWORD*)(Reloc->VirtualAddress + (Fixup[i] & 0xFFF) + (DWORD)Pe->Base) += (DWORD)Pe->Base - NT->OptionalHeader.ImageBase;
			} /*else if(RelType==IMAGE_REL_BASED_LOW)
			  {
			  *(WORD*)(Reloc->VirtualAddress+(Fixup[i]&0xFFF)+(DWORD)Pe->Base)+=(WORD)((DWORD)Pe->Base-NT->OptionalHeader.ImageBase);
			  } else if(RelType==IMAGE_REL_BASED_HIGH)
			  {
			  *(WORD*)(Reloc->VirtualAddress+(Fixup[i]&0xFFF)+(DWORD)Pe->Base)+=(WORD)(((DWORD)Pe->Base-NT->OptionalHeader.ImageBase)>>16);
			  } */ else if (RelType == IMAGE_REL_BASED_ABSOLUTE)
			{
				;	// do nothing
			}
			  else
				  LogErr("Unsupported relocation type %d\n", RelType);
			PrevReloc = Reloc->VirtualAddress + (Fixup[i] & 0xFFF);
		}
		Reloc = (IMAGE_BASE_RELOCATION*)(Reloc->SizeOfBlock + (char*)Reloc);
	}

	return TRUE;
}

// Process imports, load modules if needed
PE_EXPORT BOOL PeLdrProcessModuleImports(PE_HANDLE Pe)
{
	if (Pe->IsNative)
		return 0;

	CLock L(&CSPeLdr); L.Lock();

	DWORD Tmp;
	if (Pe->Base == 0)
	{
		SetLastError(ERROR_INVALID_HANDLE_STATE);
		return FALSE;
	}

	IMAGE_NT_HEADERS *NT = ImageNtHeader(Pe->Base);
	IMAGE_IMPORT_DESCRIPTOR *Imp = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToData(Pe->Base, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Tmp);

	if (Imp == 0)		// Module does not have imports (resource DLL for example)
		return TRUE;

	for (int i = 0; Imp[i].Name; i++)
	{
		DWORD *OrgFirstThunk = (DWORD*)((Imp[i].OriginalFirstThunk ? Imp[i].OriginalFirstThunk : Imp[i].FirstThunk) + (DWORD)Pe->Base);
		DWORD *FirstThunk = (DWORD*)(Imp[i].FirstThunk + (DWORD)Pe->Base);

		char* DLLName = (char*)((DWORD)Pe->Base + (DWORD)Imp[i].Name);

		PE_HANDLE Dll = PeLdrLoadModuleA(DLLName);
		if (Dll == 0)
		{
			LogErr("Import dll %s not found\n", DLLName);
			SetLastError(ERROR_NOT_FOUND);
			return FALSE;
		}

		for (int j = 0; OrgFirstThunk[j]; j++)
		{
			short*Ord = 0;
			IMAGE_IMPORT_BY_NAME *Nam = 0;

			if (OrgFirstThunk[j] & 0x80000000)
				Ord = (short*)(OrgFirstThunk + j);
			else
				Nam = (IMAGE_IMPORT_BY_NAME*)((DWORD)Pe->Base + (DWORD)OrgFirstThunk[j]);

			FARPROC Func = 0;
			if (Nam != 0)
			{
				Func = PeLdrGetProcAddressA(Dll, (LPCSTR)Nam->Name);
			}
			else
			{
				Func = PeLdrGetProcAddressA(Dll, (LPCSTR)*Ord);
			}

			if (Func == 0)
			{
				if (Nam == 0)
					LogErr("Import ordinal %d not found in %S\n", *Ord, Dll->FileName);
				else
					LogErr("Import %s not found in %S\n", Nam->Name, Dll->FileName);
				//				SetLastError(ERROR_NOT_FOUND);
				//				return FALSE;	// or maybe we just should point to stub?
			}

			FirstThunk[j] = (DWORD)Func;
		}

	}
	return TRUE;
}

// Returns ently (main or dllmain) of a module
PE_EXPORT DWORD PeLdrGetEntryPoint(PE_HANDLE Pe)
{
	SetLastError(0);
	if (Pe->Base == 0)
	{
		SetLastError(ERROR_INVALID_HANDLE_STATE);
		return FALSE;
	}

	IMAGE_NT_HEADERS *NT = ImageNtHeader(Pe->Base);
	return NT->OptionalHeader.AddressOfEntryPoint + (DWORD)Pe->Base;
}

// Return base addr
PE_EXPORT DWORD PeLdrGetModuleBase(PE_HANDLE Pe)
{
	if (!PeLdrIsValidHandle(Pe))
		return 0;

	if (Pe->Base == 0)
		SetLastError(ERROR_INVALID_HANDLE_STATE);
	else
		SetLastError(0);

	return (DWORD)Pe->Base;
}

// Compare file names excluding path, extension and ".86.dll"
static BOOL PeLdrAreNamesEqual(LPCWSTR Name1, LPCWSTR Name2)
{
	if (Name1 == 0 || Name2 == 0)
		return FALSE;

	const wchar_t *Ptr1 = wcsrchr(Name1, '\\');
	if (Ptr1 == 0)
		Ptr1 = Name1;
	else
		Ptr1++;
	const wchar_t *Ptr2 = wcsrchr(Name2, '\\');
	if (Ptr2 == 0)
		Ptr2 = Name2;
	else
		Ptr2++;

	if (wcslen(Ptr1) == 0 || wcslen(Ptr2) == 0)
		return FALSE;

	wchar_t *Tmp1 = (wchar_t*)alloca(wcslen(Ptr1) * 2 + 2);
	wcscpy(Tmp1, Ptr1);
	wchar_t *Tmp2 = (wchar_t*)alloca(wcslen(Ptr2) * 2 + 2);
	wcscpy(Tmp2, Ptr2);

	if (wcslen(Tmp1)>7 && _wcsicmp(Tmp1 + wcslen(Tmp1) - 7, L".86.dll") == 0)
		Tmp1[wcslen(Tmp1) - 7] = 0;
	if (wcslen(Tmp2)>7 && _wcsicmp(Tmp2 + wcslen(Tmp2) - 7, L".86.dll") == 0)
		Tmp2[wcslen(Tmp2) - 7] = 0;

	if (wcslen(Tmp1)>4 && _wcsicmp(Tmp1 + wcslen(Tmp1) - 4, L".dll") == 0)
		Tmp1[wcslen(Tmp1) - 4] = 0;
	if (wcslen(Tmp2)>4 && _wcsicmp(Tmp2 + wcslen(Tmp2) - 4, L".dll") == 0)
		Tmp2[wcslen(Tmp2) - 4] = 0;

	BOOL Ret = FALSE;

	if (_wcsicmp(Tmp1, Tmp2) == 0)
		Ret = TRUE;

	return Ret;
}

// Returns PE_HANDLE of a module if it is already in list or 0 if it is not loaded
PE_EXPORT PE_HANDLE PeLdrFindModule(LPCWSTR FileName)
{
	wchar_t Buff[1024];
	CLock L(&CSPeLdr); L.Lock();
	if (FileName && wcschr(FileName, '.') == 0)
	{
		wcscpy_s<1024>(Buff, FileName);
		wcscat_s<1024>(Buff, L".DLL");
		FileName = Buff;
	}

	for (int i = 0; i<ModulesCount; i++)
	{
		if (FileName == 0 && Modules[i]->IsExe)
			return Modules[i];
		if (PeLdrAreNamesEqual(FileName, Modules[i]->FileName))
			return Modules[i];
	}
	return 0;
}

PE_EXPORT PE_HANDLE PeLdrLoadModule(LPCWSTR FileName)
{
	CLock L(&CSPeLdr); L.Lock();

	PE_HANDLE Tmp = PeLdrFindModule(FileName);
	if (Tmp)
		return Tmp;

	PE_HANDLE PE = PeLdrOpenModule(FileName);
	if (!PE)
		return NULL;
	if (PE->IsNative)
		return PE;
	DWORD DesiredBase = PeLdrGetFixedLoadAddress(PE);
	if (PeLdrInternalLoadModule(PE, (void*)DesiredBase))
		return PE;
	return NULL;
}

// The same as PeLdrLoadModule but ansi
PE_EXPORT PE_HANDLE PeLdrLoadModuleA(LPCSTR FileNameA)
{
	wchar_t Buff[10240];
	_snwprintf_s<10240>(Buff, 10240, L"%S", FileNameA);

	return PeLdrLoadModule(Buff);
}

// The same as PeLdrFindModule but ansi
PE_EXPORT PE_HANDLE PeLdrFindModuleA(LPCSTR FileNameA)
{
	if (FileNameA == NULL)
		return PeLdrFindModule(NULL);

	wchar_t Buff[10240];
	_snwprintf_s<10240>(Buff, 10240, L"%S", FileNameA);

	return PeLdrFindModule(Buff);
}

PE_EXPORT FARPROC PeLdrGetProcAddress(PE_HANDLE Pe, LPCWSTR Name)
{
	char Buff[10240];
	_snprintf_s<10240>(Buff, 10240, "%S", Name);

	return PeLdrGetProcAddressA(Pe, Buff);
}

// == Windows API GetProcAddress, calls hook first
// If 1st param==0 - scans all loaded modules for export with given name
PE_EXPORT FARPROC PeLdrGetProcAddressInternal(PE_HANDLE Pe, LPCSTR Name)
{
	CLock L(&CSPeLdr); L.Lock();

	if (Pe == 0)
	{
		for (int i = 0; i<ModulesCount; i++)
		{
			FARPROC Ret = 0;
			if (Modules[i])
				Ret = PeLdrGetProcAddressA(Modules[i], Name);
			if (Ret)
				return Ret;
		}
	}

	if (!PeLdrIsValidHandle(Pe))
		return 0;

	if ((DWORD)Name<65536)
	{
		char Buff[16];
		sprintf_s<16>(Buff, "Ord_%d", (DWORD)Name);
		FARPROC Ret = PeLdrGetProcAddressA(Pe, Buff);
		if (Ret)
			return Ret;
	}

	if (Pe->IsNative)
		return 0;

	DWORD Tmp;
	if (Pe->Base == 0)
	{
		SetLastError(ERROR_INVALID_HANDLE_STATE);
		return 0;
	}

	IMAGE_NT_HEADERS *NT = ImageNtHeader(Pe->Base);
	IMAGE_EXPORT_DIRECTORY *Exp = (IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(Pe->Base, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &Tmp);
	if (Exp == 0 || Exp->NumberOfFunctions == 0)
	{
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

	DWORD *Names = (DWORD*)(Exp->AddressOfNames + (DWORD)Pe->Base);
	WORD *Ordinals = (WORD*)(Exp->AddressOfNameOrdinals + (DWORD)Pe->Base);
	DWORD *Functions = (DWORD*)(Exp->AddressOfFunctions + (DWORD)Pe->Base);

	FARPROC Ret = 0;

	char Buff[32];
	if (Pe->IsStub)
	{
		if ((DWORD)Name<65536)	// Stub DLLs export only by names
		{
			sprintf_s<32>(Buff, "_stub_Ord%d", (DWORD)Name);
			Name = Buff;
		}

		for (DWORD i = 0; i<Exp->NumberOfNames && Ret == 0; i++)
		{
			char Buff[1024];
			char *Func = (char*)(Names[i] + (DWORD)Pe->Base);
			if (Func)
			{
				strcpy_s<1024>(Buff, Func);
				char *T = strrchr(Buff, '@');
				if (T)
					*T = 0;
				char *Ptr = Buff;
				if (memcmp(Buff, "_stub_", 6) == 0)
					Ptr = Buff + 6;

				if (strcmp(Name, Ptr) == 0)
					Ret = (FARPROC)(Functions[Ordinals[i]] + (DWORD)Pe->Base);
			}
		}
	}
	else
	{
		if ((DWORD)Name<65536)
		{
			if ((DWORD)Name - Exp->Base<Exp->NumberOfFunctions)
				Ret = (FARPROC)(Functions[(DWORD)Name - Exp->Base] + (DWORD)Pe->Base);
		}
		else
		{
			for (DWORD i = 0; i<Exp->NumberOfNames && Ret == 0; i++)
			{
				char *Func = (char*)(Names[i] + (DWORD)Pe->Base);
				if (Func && strcmp(Func, Name) == 0)
					Ret = (FARPROC)(Functions[Ordinals[i]] + (DWORD)Pe->Base);
			}
		}
	}

	if (Ret)
	{
		DWORD ExpStart = NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (DWORD)Pe->Base;
		DWORD ExpSize = NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		if ((DWORD)Ret >= ExpStart && (DWORD)Ret <= ExpStart + ExpSize)
		{
			// forwarder
			char Buff[1024];
			strcpy_s<1024>(Buff, (char*)Ret);
			char *Func = strrchr(Buff, '.');
			if (Func == 0)
			{
				SetLastError(ERROR_NOT_FOUND);
				return 0;
			}
			*Func = 0; Func++;
			char Buf1[1024];
			strcpy_s<1024>(Buf1, Buff);
			strcat_s<1024>(Buf1, ".DLL");
			PE_HANDLE Dll = PeLdrLoadModuleA(Buf1);
			if (Dll == 0)
				return 0;
			if (Func[0] == '#')
				Func = (char*)atoi(Func + 1);
			return PeLdrGetProcAddressA(Dll, Func);
		}
		return Ret;
	}

	SetLastError(ERROR_NOT_FOUND);
	return 0;
}

PE_EXPORT FARPROC PeLdrGetProcAddressA(PE_HANDLE Pe, LPCSTR Name)
{
	__try
	{
		return PeLdrGetProcAddressInternal(Pe, Name);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	SetLastError(ERROR_NOT_FOUND);
	return 0;
}

PE_EXPORT PE_HANDLE PeLdrFindModuleByBase(DWORD Base)
{
	CLock L(&CSPeLdr); L.Lock();

	for (int i = 0; i<ModulesCount; i++)
	{
		if (Base == 0 && Modules[i]->IsExe)
			return Modules[i];
		if (Base == (DWORD)Modules[i]->Base)
			return Modules[i];
	}
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
}

struct ExeValidator
{
	LPCWSTR ExePath;
	BOOL IsValid;
	BOOL IsGUI;
};

DWORD WINAPI ValidatorThreadProc(
	_In_  LPVOID lpParameter
)
{
	__try {
		ExeValidator *Ev = (ExeValidator*)lpParameter;
		Ev->IsValid = FALSE;
		Ev->IsGUI = TRUE;
		PE_HANDLE Tmp = PeLdrOpenModuleNoAdd(Ev->ExePath);
		if (Tmp == 0)
		{
			LogInfo("%S is not a valid x86 EXE", Ev->ExePath);
			return FALSE;
		}
		Ev->IsGUI = Tmp->IsGUI;
		PeLdrCloseModule(Tmp);
		if (Tmp->IsExe)
			Ev->IsValid = TRUE;
		if (Ev->IsGUI)
			LogInfo("%S is a valid x86 GUI EXE", Ev->ExePath);
		else
			LogInfo("%S is a valid x86 console EXE", Ev->ExePath);
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

static ExeValidator Ev;
// Check the file existence and validate it a bit
PE_EXPORT int PeLdrIsValidX86(LPCWSTR ExePath)
{
	if (ExePath == 0)
		return FALSE;
	Ev.ExePath = ExePath;
	Ev.IsValid = FALSE;
	Ev.IsGUI = TRUE;
	__try {
		/*		HANDLE Ht=CreateThread(0,0,ValidatorThreadProc,&Ev,0,0);	// Need to create a different thread as we have too small stack in CreateProcessInternal that calls this func
		if(Ht==0)
		return FALSE;
		WaitForSingleObject(Ht,1000);
		//TerminateThread(Ht,0);	-- don't do this as this would keep locks held!
		CloseHandle(Ht);*/
		ValidatorThreadProc(&Ev);

		if (Ev.IsValid)
		{
			if (Ev.IsGUI)
				return 1;
			else
				return -1;
		}
		return 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}
