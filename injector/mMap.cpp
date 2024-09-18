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

	// Mapping modules (must be done before import resolution)

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

		if (!MapDLL(process, data)) {
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

		if (!ResolveImports(data, modules, LoadedModules)) {
			return false;
		}
	}

	// Freeing images & modules data

	for (module_data& data : modules)
	{
		delete[] data.ImageBase;
	} 

	modules.clear();

	for (module_data& data : LoadedModules)
	{
		if (data.ImageBase) {
			delete[] data.ImageBase;
		}
	}

	LoadedModules.clear();

	return true;
} 