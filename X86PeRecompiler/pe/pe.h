#pragma once

class PeFile
{
public:
	PeFile(char* data, int size);

private:
	char* data;
	int size;
	int datap;

	int ntStart;
	int numberOfSections;

	void readDosHeader();
	void readNtHeader();

	int rvaToFileOffset(int rva);
};