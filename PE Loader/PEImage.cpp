#include "PEImage.hpp"

PEImage::PEImage(uintptr_t* buffer)
{
	image_address = uintptr_t(buffer);
	pDosHeader = PIMAGE_DOS_HEADER(buffer);
	pNtHeaders = PIMAGE_NT_HEADERS(image_address + pDosHeader->e_lfanew);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeaders->Signature != IMAGE_NT_SIGNATURE || pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		std::cout << "Error parsing PE Headers" << std::endl;
		exit(0);
	}
		
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
	IMAGE_DATA_DIRECTORY reloc_table = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	uintptr_t reloc_table_offset = resolveRVA(reloc_table.VirtualAddress);
	uintptr_t offset = 0;
	ptrdiff_t image_base_delta = actual_base - image_base;
	if (image_base_delta == 0 || reloc_table.Size == 0)
		return;

	while (offset < reloc_table.Size)
	{
		PIMAGE_BASE_RELOCATION pBaseReloc = PIMAGE_BASE_RELOCATION(image_address + reloc_table_offset + offset);
		offset += sizeof(IMAGE_BASE_RELOCATION);
		size_t entries = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PIMAGE_RELOCATION_ENTRY pRelocationEntry = PIMAGE_RELOCATION_ENTRY(uintptr_t(pBaseReloc) + sizeof(IMAGE_BASE_RELOCATION));
		for (size_t i = 0; i < entries; i++, pRelocationEntry++)
		{
			offset += sizeof(IMAGE_RELOCATION_ENTRY);
			uintptr_t baseRelocationOffset = resolveRVA(pBaseReloc->VirtualAddress);
			uintptr_t rawRelocationAddress = image_address + baseRelocationOffset + pRelocationEntry->Offset;
			switch (pRelocationEntry->Type)
			{
			case IMAGE_REL_BASED_HIGH:
			{
				PSHORT pRelocationAddress = PSHORT(rawRelocationAddress);
				*pRelocationAddress += HIWORD(image_base_delta);
			}
			case IMAGE_REL_BASED_LOW:
			{
				PSHORT pRelocationAddress = PSHORT(rawRelocationAddress);
				*pRelocationAddress += LOWORD(image_base_delta);
			}
			case IMAGE_REL_BASED_HIGHLOW:
			{
				PDWORD32 pRelocationAddress = PDWORD32(rawRelocationAddress);
				*pRelocationAddress += DWORD32(image_base_delta);
			}
			case IMAGE_REL_BASED_DIR64:
			{
				PDWORD64 pRelocationAddress = PDWORD64(rawRelocationAddress);
				*pRelocationAddress += image_base_delta;
			}
			default:
				continue;
			}
		}
	}
}

void PEImage::resolveImports()
{
	uintptr_t import_table_offset = resolveRVA(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = PIMAGE_IMPORT_DESCRIPTOR(image_address + import_table_offset);
	for (; pImportDesc->Name; pImportDesc++)
	{
		uintptr_t import_name_offset = resolveRVA(pImportDesc->Name);
		PCHAR pImportName = PCHAR(image_address + import_name_offset);
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
		HMODULE import_lib = LoadLibraryA(pImportName);
		if (!import_lib) 
		{
			std::cout << "Couldn't find library: " << pImportName << std::endl;
			continue;
		}
		for (; pThunkData->u1.AddressOfData; pThunkData++, pFirstThunk++)
		{
			if (~pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				PIMAGE_IMPORT_BY_NAME pThunkName = PIMAGE_IMPORT_BY_NAME(image_address + resolveRVA(pThunkData->u1.AddressOfData));
				uintptr_t function_addr = uintptr_t(GetProcAddress(import_lib, pThunkName->Name));
				pFirstThunk->u1.Function = function_addr;
			}
			else
			{
				uintptr_t function_addr = getExport(import_lib, IMAGE_ORDINAL(pThunkData->u1.Ordinal));
				pFirstThunk->u1.Function = function_addr;
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

uintptr_t PEImage::getExport(HMODULE library_handle, uint32_t biased_ordinal)
{
	uintptr_t module_base = uintptr_t(library_handle);
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(module_base);
	PIMAGE_NT_HEADERS pNtHeaders = PIMAGE_NT_HEADERS(module_base + pDosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY export_table_dir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY pExportDir = PIMAGE_EXPORT_DIRECTORY(module_base + export_table_dir.VirtualAddress);
	PDWORD pAddressTable = PDWORD(module_base + pExportDir->AddressOfFunctions);
	uint32_t ordinal = biased_ordinal - pExportDir->Base;

	return module_base + pAddressTable[ordinal];
}