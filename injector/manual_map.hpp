#pragma once

struct module_data
{
	BYTE* ImageBase;
	IMAGE_NT_HEADERS32* NT_HEADERS;
	IMAGE_SECTION_HEADER* sections;

	bool IsLoaded; // indicates whether or not the module is already loaded within the target process
	HMODULE RemoteHandle;
};

bool ManualMapDll(const HANDLE process, const char* DllPath);