#pragma once

#include <Windows.h>
#include <vector>
#include <iostream>
#include <fstream>

LPCWSTR convertStr(char* str);

std::vector<byte> getFile(LPCSTR fileName);