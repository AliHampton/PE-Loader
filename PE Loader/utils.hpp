#pragma once

#include <Windows.h>
#include <vector>
#include <iostream>
#include <fstream>

LPCWSTR convertStr(char* str);

std::vector<uint8_t> getFile(LPCSTR fileName);