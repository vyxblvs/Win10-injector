#include "pch.h"
#include "mMap.hpp"
#include "parsing.hpp"
#include "process.hpp"
#include "injector.hpp"

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

	// Resolving dependencies for unloaded modules

	std::vector<API_DATA> ApiSets;
	for (UINT i = 0; i < modules.size(); ++i)
	{
		if (modules[i].IsApiSet) continue;

		if (!GetDependencies(process, &modules[i], modules, LoadedModules, ApiSets, i))
			return false;
	}

	// Allocating memory for modules

	for (auto& data : modules)
	{
		if (data.IsApiSet) continue;

		data.lpvRemoteBase = __VirtualAllocEx(process, data.NT_HEADERS->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);

		if (!data.lpvRemoteBase)
		{
			PrintError("VirtualAllocEx[lpvRemoteBase]");
			return false;
		}
	}

	// Getting the host modules for all API sets 

	for (auto& data : modules)
	{
		if (!data.IsApiSet) continue;

		if (!GetApiHost(data, ApiSets, modules, LoadedModules))
			return false;
	}

	// Applying relocation and resolving imports

	for (module_data& data : modules)
	{
		if (data.IsApiSet) continue;
		
		if (!ApplyRelocation(data)) 
			return false;

		// ResolveImports will also get the EP of the target module
		if (!ResolveImports(data, modules, LoadedModules, ApiSets)) 
			return false;
	}

	// Freeing LoadedModules

	for (auto& data : LoadedModules)
	{
		if (data.ImageBase) delete[] data.ImageBase;
	}

	LoadedModules.clear();

	// Mapping modules

	for (auto& data : modules)
	{
		if (data.IsApiSet) continue;
		
		if (!MapDLL(process, data))
			return false;
	}

	RunDllMain(process, modules[0]);

	// Freeing modules

	for (auto& data : modules)
	{
		delete[] data.ImageBase;
	} 

	modules.clear();

	return true;
} 