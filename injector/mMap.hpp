#pragma once

/*
* RESOURCES
* 
* > IMAGE LOADER
* - Image Loader internals: https://empyreal96.github.io/nt-info-depot/Windows-Internals-PDFs/Windows%20System%20Internals%207e%20Part%201.pdf
* 
* > PE PARSING
* - PE Format: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
* 
* > DEPENDENCY RESOLUTION (ties closely with image loader internals)
* - DLL Search Order: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
* - DLL Redirection: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection
* 
* > API Sets (ties in closely with dependency resolution and image loader internals)
* - API Sets: https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets 
* - API Set Loader Operation: https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation
* - The API Set Schema: https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
*/

#define unloaded 0

#define loaded   1

struct API_DATA
{
	int HostPos = -1;
	int HostVec;
};

struct module_data
{
	std::string path;
	std::string name;

	bool IsApiSet = false;
	BYTE* ImageBase = nullptr;

	IMAGE_NT_HEADERS32* NT_HEADERS;
	IMAGE_SECTION_HEADER* sections;
	
	union
	{
		void* lpvRemoteBase;
		DWORD RemoteBase;
		ULONG ApiDataPos;
	};
};

extern std::vector<API_DATA> ApiSets;
extern std::vector<module_data> LoadedModules, modules;

bool ManualMapDll(const HANDLE process, const char* DllPath);