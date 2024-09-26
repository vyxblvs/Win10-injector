#include "pch.h"
#include "mMap.hpp"
#include "parsing.hpp"
#include "process.hpp"
#include "injector.hpp"

std::vector<API_DATA> ApiSets;
std::vector<DLL_DATA> LoadedModules, modules;

bool ManualMapDll(const HANDLE process, const char* DllPath)
{
	modules.push_back({});

	if (!LoadDll(DllPath, &modules.back())) {
		return false;
	}

	if (!GetLoadedModules(process)) {
		return false;
	}

	// Resolving dependencies for unloaded modules

	for (UINT i = 0; i < modules.size(); ++i)
	{
		if (modules[i].IsApiSet) continue;

		if (!GetDependencies(process, &modules[i], i))
			return false;
	}

	// Allocating memory for modules

	for (auto& dll : modules)
	{
		if (dll.IsApiSet) continue;

		dll.pRemoteBase = __VirtualAllocEx(process, dll.NT_HEADERS->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);

		if (!dll.pRemoteBase)
		{
			PrintError("VirtualAllocEx[pRemoteBase]");
			return false;
		}
	}

	// Getting the host modules for all API sets 

	for (auto& dll : modules)
	{
		if (!dll.IsApiSet) continue;

		if (!ResolveApiHost(dll))
			return false;
	}

	// Applying relocation and resolving imports

	for (UINT i = 0; i < modules.size(); ++i)
	{
		if (modules[i].IsApiSet) continue;
		
		if (!ApplyRelocation(modules[i]))
			return false;

		if (!ResolveImports(process, &modules[i], i))
			return false;
	}

	// Mapping modules

	for (auto& dll : modules)
	{
		if (dll.IsApiSet) continue;
		
		if (!MapDLL(process, dll))
			return false;
	}

	return RunDllMain(process, modules[0]);
} 