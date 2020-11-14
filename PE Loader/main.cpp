#include "PEImage.hpp"
#include "utils.hpp"

int main()
{
	std::vector<uint8_t> file = getFile("FILE PATH");
	PEImage image((uintptr_t*)file.data());
	void* pImageBase = VirtualAlloc(NULL, image.getSize(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	uintptr_t imageBase = uintptr_t(pImageBase);
	image.resolveImports();
	image.processRelocations(imageBase);
	image.mapImage(imageBase);
	uintptr_t entryAddress = imageBase + image.getEntryPoint();
	((int(*)(void))entryAddress)();
	return 0;
}