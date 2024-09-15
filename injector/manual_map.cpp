#include "pch.h"
#include "manual_map.hpp"
#include "file_parsing.hpp"

/*
*  CURRENT GOAL(s)
*  - Get dependencies
*  - Apply relocation
*/

bool ManualMapDll(const HANDLE process, const char* DllPath)
{
	std::vector<module_data> modules;
	modules.push_back({});

	if (!LoadDLL(DllPath, &modules.back())) {
		return false;
	}

	GetDependencies(modules.back(), modules);

	return true;
} 