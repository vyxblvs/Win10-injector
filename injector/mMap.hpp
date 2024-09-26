#pragma once

#define unloaded 0

#define loaded   1

struct API_DATA
{
	int HostPos = -1;
	bool HostVec;
};

struct DLL_DATA
{
	std::string path;
	std::string name;

	bool IsApiSet = false;
	BYTE* ImageBase = nullptr;

	IMAGE_NT_HEADERS32* NT_HEADERS;
	IMAGE_SECTION_HEADER* sections;
	
	union
	{
		void* pRemoteBase;
		DWORD RemoteBase;
		ULONG ApiDataPos;
	};
};

extern std::vector<API_DATA> ApiSets;
extern std::vector<DLL_DATA> LoadedModules, modules;

bool ManualMapDll(const HANDLE process, const char* DllPath);