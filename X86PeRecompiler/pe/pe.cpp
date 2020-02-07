#include "pe.h"
#include <Windows.h>

#define STRING_INVALID_SIZE "invalid size"
#define STRING_INVALID_SIGN "invalid signature"
#define STRING_NT_NOT_READY "NT Header not readed yet"

PeFile::PeFile(char * data, int size)
	:data(data), size(size), datap(0),
	ntStart(-1), numberOfSections(-1)
{
	readDosHeader();
}

void PeFile::readDosHeader()
{
	if (size <= sizeof(IMAGE_DOS_HEADER))
	{
		throw STRING_INVALID_SIZE;
	}
	IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER*)data;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		throw STRING_INVALID_SIGN;
	}
	if (dosHeader->e_lfanew >= size)
	{
		throw STRING_INVALID_SIZE;
	}
	datap = dosHeader->e_lfanew;
	ntStart = dosHeader->e_lfanew;
}

void PeFile::readNtHeader()
{
	if (size - datap <= sizeof(IMAGE_NT_HEADERS32))
	{
		throw STRING_INVALID_SIZE;
	}
	IMAGE_NT_HEADERS32 *ntHeader = (IMAGE_NT_HEADERS32*)(data + datap);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		throw STRING_INVALID_SIGN;
	}
	if (ntHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		throw "support x86(32bit only) only now";
	}
	numberOfSections = ntHeader->FileHeader.NumberOfSections;
	IMAGE_DATA_DIRECTORY* export_dir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	int export_rva = export_dir->VirtualAddress;
	int export_size = export_dir->Size;

	int export_pos = rvaToFileOffset(export_rva);
	if (export_pos == -1)
	{
		throw "invalid export table address";
	}




}

int PeFile::rvaToFileOffset(int rva)
{
	if (ntStart == -1 || numberOfSections)
	{
		throw STRING_NT_NOT_READY;
	}

	int secTableStart = ntStart + sizeof(IMAGE_NT_HEADERS32);
	IMAGE_SECTION_HEADER* sectionTable = (IMAGE_SECTION_HEADER*)(data + secTableStart);
	for (int i = 0; i < numberOfSections; i++)
	{
		int tmp_offset = rva - sectionTable[i].VirtualAddress;
		if (tmp_offset >= 0 && tmp_offset < sectionTable[i].Misc.VirtualSize)
		{
			return sectionTable[i].PointerToRawData + tmp_offset;
		}
	}

	return -1;//not found
}

