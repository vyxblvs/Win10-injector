#include "pch.h"
#include "mMap.hpp"
#include "process.hpp"
#include "injector.hpp"
#include "parsing.hpp"

bool GetLoadedModules(HANDLE process, std::vector<module_data>& buffer)
{
	DWORD sz;
	HMODULE handles[1024];
	if (!EnumProcessModules(process, handles, sizeof(handles), &sz))
	{
		PrintError("EnumProcessModules");
		return false;
	}

	sz /= sizeof(HMODULE);
	for (int i = 0; i < sz; ++i)
	{
		char path[MAX_PATH];
		if (!GetModuleFileNameExA(process, handles[i], path, MAX_PATH))
		{
			PrintError("GetModuleFileNameExA");
			return false;
		}

		buffer.push_back({});

		std::string& ModulePath = buffer.back().path;
		ModulePath = path;

		buffer.back().name = ModulePath.substr(ModulePath.find_last_of('\\') + 1);
	}
}