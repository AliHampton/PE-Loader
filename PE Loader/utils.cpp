#include "utils.hpp"

LPCWSTR convertStr(char* str)
{
	size_t newsize = strlen(str) + 1;
	wchar_t* wcstring = new wchar_t[newsize];
	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, wcstring, newsize, str, _TRUNCATE);
	return LPCWSTR(wcstring);
}

std::vector<uint8_t> getFile(LPCSTR fileName)
{
	std::ifstream file(fileName, std::ios::in | std::ios::binary | std::ios::ate);
	std::vector<uint8_t> contents;
	if (file.is_open())
	{
		file.unsetf(std::ios::skipws);
		file.seekg(0, std::ios::beg);
		contents.reserve(file.tellg());
		contents.insert(contents.begin(), std::istream_iterator<uint8_t>(file), std::istream_iterator<uint8_t>());
		file.close();
	}
	return contents;
}