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

	for (int i = 0; i < modules.size(); ++i)
	{
		if (modules[i].IsAPIset) {
			continue;
		}

		if (!GetDependencies(process, &modules[i], modules, LoadedModules, i)) {
			return false;
		}
	}

	// Allocating memory for modules

	for (module_data& data : modules)
	{
		if (data.IsAPIset) {
			continue;
		}

		const size_t sz = data.NT_HEADERS->OptionalHeader.SizeOfImage;
		data.lpvRemoteBase = VirtualAllocEx(process, nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
		if (!data.lpvRemoteBase)
		{
			PrintError("VirtualAllocEx[lpvRemoteBase]");
			return false;
		}
	}

	// Applying relocation and resolving imports

	for (module_data& data : modules)
	{
		if (data.IsAPIset) {
			continue;
		}

		if (!ApplyRelocation(data)) {
			return false;
		}

		// ResolveImports will also get the EP of the target module
		if (!ResolveImports(data, modules, LoadedModules)) {
			return false;
		}
	}

	// Freeing LoadedModules

	for (module_data& data : LoadedModules)
	{
		if (data.ImageBase) {
			delete[] data.ImageBase;
		}
	}

	LoadedModules.clear();

	// Mapping modules

	for (module_data& data : modules)
	{
		if (data.IsAPIset) {
			continue;
		}

		if (!MapDLL(process, data)) {
			return false;
		}
	}

	// Freeing modules

	for (module_data& data : modules)
	{
		delete[] data.ImageBase;
	} 

	modules.clear();

	return true;
} 