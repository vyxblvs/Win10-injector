#include "pch.h"
#include "mMap.hpp"
#include "parsing.hpp"
#include "process.hpp"

/*
*  CURRENT GOAL(s)
*  - Get dependencies
*  - Apply relocation
*/

bool ManualMapDll(const HANDLE process, const char* DllPath)
{
	std::vector<module_data> LoadedModules, modules;
	modules.push_back({});

	if (!LoadDLL(DllPath, &modules.back())) {
		return false;
	}

	if (!GetLoadedModules(process, LoadedModules)) {
		return false;
	}

	for (int i = 0; i < modules.size(); ++i)
	{
		if (!GetDependencies(process, &modules.back(), modules, LoadedModules, modules.size() - 1)) {
			return false;
		}


	}

	return true;
} 