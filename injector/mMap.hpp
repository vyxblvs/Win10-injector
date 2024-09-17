#pragma once

/*
* RESOURCES
* 
* > PE PARSING
* - PE Format: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
* 
* > DEPENDENCY RESOLUTION 
* - DLL Search Order: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
* - DLL Redirection: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection
* - API Sets: https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets 
* - API Set Loader Operation: https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation
*/


struct module_data
{
	std::string path;
	std::string name;

	bool ApiSet = false;
	BYTE* ImageBase = nullptr;
	IMAGE_NT_HEADERS32* NT_HEADERS;
	IMAGE_SECTION_HEADER* sections;

	union
	{
		void* lpvRemoteBase;
		DWORD RemoteBase;
	};
};

bool ManualMapDll(const HANDLE process, const char* DllPath);