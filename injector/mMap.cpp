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
		if (modules.back().ApiSet == true) {
			continue;
		}

		if (!GetDependencies(process, &modules.back(), modules, LoadedModules, modules.size() - 1)) {
			return false;
		}
	}

	// Allocating memory in target process for mapping

	for (int i = 0; i < modules.size(); ++i)
	{
		if (modules[i].ApiSet == true) {
			continue;
		}

		const size_t sz = modules[i].NT_HEADERS->OptionalHeader.SizeOfImage;
		modules[i].lpvRemoteBase = VirtualAllocEx(process, nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
		if (!modules[i].lpvRemoteBase)
		{
			PrintError("VirtualAllocEx[lpvRemoteBase]");
			return false;
		}
	}

	// Applying relocation and resolving imports

	for (int i = 0; i < modules.size(); ++i)
	{
		if (modules[i].ApiSet == true) {
			continue;
		}

		if (!ApplyRelocation(modules[i])) {
			return false;
		}

		std::cout << "RELOCATED: " << std::hex << modules[i].RemoteBase << '\n';
	}

	return true;
} 