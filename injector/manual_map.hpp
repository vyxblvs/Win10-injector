#pragma once

struct module_data
{
	char* ImageBase = nullptr;
	PIMAGE_NT_HEADERS32 NT_HEADERS = nullptr;
};

bool ManualMapDll(const HANDLE process, const char* DllPath);