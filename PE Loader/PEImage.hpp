#pragma once

#include <vector>
#include <iostream>
#include <Windows.h>
#include "utils.hpp"

typedef struct _IMAGE_RELOCATION_ENTRY
{
	USHORT Offset : 12;
	USHORT Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

class PEImage
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	uintptr_t image_address;
	uintptr_t size;
	uintptr_t image_base;
	uintptr_t entry_point;

	uintptr_t resolveRVA(uintptr_t RVA);

public:
	PEImage(uintptr_t* buffer);
	void mapImage(uintptr_t target_address);
	void processRelocations(uintptr_t actual_base);
	void resolveImports();
	uintptr_t getSize();
	uintptr_t getEntryPoint();
};