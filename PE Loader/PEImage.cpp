#include "PEImage.hpp"

PEImage::PEImage(uintptr_t* buffer)
{
	image_address = uintptr_t(buffer);
	pDosHeader = PIMAGE_DOS_HEADER(buffer);
	pNtHeaders = PIMAGE_NT_HEADERS(image_address + pDosHeader->e_lfanew);
	size = pNtHeaders->OptionalHeader.SizeOfImage;
	image_base = pNtHeaders->OptionalHeader.ImageBase;
	entry_point = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
}

void PEImage::mapImage(uintptr_t target_address)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
		if (~pSectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			memcpy((uintptr_t*)(target_address + pSectionHeader->VirtualAddress), (uintptr_t*)(image_address + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData);
}

void PEImage::processRelocations(uintptr_t actual_base)
{
	IMAGE_DATA_DIRECTORY relocationTable = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	uintptr_t relocTableOffset = resolveRVA(relocationTable.VirtualAddress);
	uintptr_t offset = 0;
	uintptr_t imageBaseDelta = actual_base - image_base;
	if (imageBaseDelta == 0 || relocationTable.Size == 0)
		return;
	while (offset < relocationTable.Size)
	{
		PIMAGE_BASE_RELOCATION pBaseReloc = PIMAGE_BASE_RELOCATION(image_address + relocTableOffset + offset);
		offset += sizeof(IMAGE_BASE_RELOCATION);
		int numEntries = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PIMAGE_RELOCATION_ENTRY pRelocationEntry = PIMAGE_RELOCATION_ENTRY(uintptr_t(pBaseReloc) + sizeof(IMAGE_BASE_RELOCATION));
		for (int i = 0; i < numEntries; i++, pRelocationEntry++)
		{
			offset += sizeof(IMAGE_RELOCATION_ENTRY);
			uintptr_t baseRelocationOffset = resolveRVA(pBaseReloc->VirtualAddress);
			uintptr_t rawRelocationAddress = image_address + baseRelocationOffset + pRelocationEntry->Offset;
			switch (pRelocationEntry->Type)
			{
			case IMAGE_REL_BASED_HIGH:
			{
				PSHORT pRelocationAddress = PSHORT(rawRelocationAddress);
				*pRelocationAddress += HIWORD(imageBaseDelta);
			}
			case IMAGE_REL_BASED_LOW:
			{
				PSHORT pRelocationAddress = PSHORT(rawRelocationAddress);
				*pRelocationAddress += LOWORD(imageBaseDelta);
			}
			case IMAGE_REL_BASED_HIGHLOW:
			{
				PDWORD32 pRelocationAddress = PDWORD32(rawRelocationAddress);
				*pRelocationAddress += DWORD32(imageBaseDelta);
			}
			case IMAGE_REL_BASED_DIR64:
			{
				PDWORD64 pRelocationAddress = PDWORD64(rawRelocationAddress);
				*pRelocationAddress += imageBaseDelta;
			}
			default:
				continue;
			}
		}
	}
}

void PEImage::resolveImports()
{
	uintptr_t importTableOffset = resolveRVA(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = PIMAGE_IMPORT_DESCRIPTOR(image_address + importTableOffset);
	for (; pImportDesc->Name; pImportDesc++)
	{
		uintptr_t importNameOffset = resolveRVA(pImportDesc->Name);
		PCHAR pImportName = PCHAR(image_address + importNameOffset);
		PIMAGE_THUNK_DATA pThunkData;
		PIMAGE_THUNK_DATA pFirstThunk = PIMAGE_THUNK_DATA(image_address + resolveRVA(pImportDesc->FirstThunk));
		if (pImportDesc->OriginalFirstThunk)
		{
			pThunkData = PIMAGE_THUNK_DATA(image_address + resolveRVA(pImportDesc->OriginalFirstThunk));
		}
		else
		{
			pThunkData = pFirstThunk;
		}
		HMODULE importLib = LoadLibrary(convertStr(pImportName));
		for (; pThunkData->u1.AddressOfData; pThunkData++, pFirstThunk++)
		{
			if (!(pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				PIMAGE_IMPORT_BY_NAME pThunkName = PIMAGE_IMPORT_BY_NAME(image_address + resolveRVA(pThunkData->u1.AddressOfData));
				uintptr_t functionAddress = uintptr_t(GetProcAddress(importLib, pThunkName->Name));
				pFirstThunk->u1.Function = functionAddress;
			}
			else
			{
				std::cout << "ORDINAL" << std::endl;
				exit(0);
			}
		}
	}
}

uintptr_t PEImage::resolveRVA(uintptr_t RVA)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections - 1; i++, pSectionHeader++)
	{
		if (RVA < (pSectionHeader + 1)->VirtualAddress)
			break;
	}
	return RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
}

uintptr_t PEImage::getSize()
{
	return size;
}

uintptr_t PEImage::getEntryPoint()
{
	return entry_point;
}