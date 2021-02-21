#include "PEImage.hpp"
#include "utils.hpp"

int main(int args_count, char* args[])
{
	if (args_count < 2)
	{
		std::cout << "Please specify a file to map" << std::endl;
		return 0;
	}
	std::vector<byte> file = getFile(args[1]);
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