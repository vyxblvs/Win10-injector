#include "pch.h"
#include "mMap.hpp"
#include "parsing.hpp"
#include "helpers.hpp"
#include "injector.hpp"

bool IsApiSet(std::string DllName)
{
	// API Set naming conventions: https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets

	for (auto& ch : DllName) {
		ch = std::tolower(static_cast<int>(ch));
	}
	
	UINT pos = DllName.size() - 4;
	if (DllName.substr(pos) == ".dll")
		DllName.erase(pos);

	const std::string ExtensionType = DllName.substr(0, 4);
	if (ExtensionType != "api-" && ExtensionType != "ext-")
		return false;

	pos = DllName.size() - 6; // start of end sequence
	if (DllName[pos] != 'l')
		return false;

	for (UINT i = pos + 1; i < pos + 6; ++i)
	{
		if ((i - pos) % 2 == 0)
		{
			if (DllName[i] != '-')
				return false;
		}

		else if (!std::isdigit(static_cast<int>(DllName[i])))
			return false;
	}

	return true;
}

bool GetModule(HANDLE process, const std::string& DllName, DLL_DATA* buffer)
{
	// Checking if the module is an API set, retrieving it from Windows\SysWOW64\downlevel if so
	// Once the injector is functional, the module location process will be updated to match the Windows DLL Loader

	std::string SysWOW(MAX_PATH, 0);
	const UINT WinDirSz = GetWindowsDirectoryA(SysWOW.data(), MAX_PATH);
	SysWOW.resize(WinDirSz);
	SysWOW += "\\SysWOW64\\";

	if (IsApiSet(DllName))
	{
		const std::string APIpath = SysWOW + "downlevel\\" + DllName;

		if (PathFileExistsA(APIpath.c_str()))
		{
			buffer->IsApiSet = true;
			return LoadDll(APIpath.c_str(), buffer);
		}
		else return PrintError("FAILED TO LOCATE API SET");
	}

	// Checking Windows\SysWOW64

	std::string DllPath = SysWOW + DllName;

	if (PathFileExistsA(DllPath.c_str())) {
		return LoadDll(DllPath.c_str(), buffer);
	}

	// Checking target process folder

	DWORD sz = 256;
	DllPath.clear();
	DllPath.resize(sz);
	if (QueryFullProcessImageNameA(process, 0, DllPath.data(), &sz) == 0) {
		return PrintError("QueryFullProcessImageNameA");
	}

	DllPath.erase(DllPath.find_last_of('\\') + 1, DllPath.size());
	DllPath += DllName;

	if (PathFileExistsA(DllPath.c_str())) {
		return LoadDll(DllPath.c_str(), buffer);
	}

	return PrintError("FAILED TO LOCATE MODULE");
}

DLL_DATA* GetDllData(const char* name, int* pos, int* DllVec)
{
	std::vector<DLL_DATA>* ModuleVector = &modules;

	for (int v = 0; v < 2; ++v, ModuleVector = &LoadedModules)
	{
		for (UINT i = 0; i < ModuleVector->size(); ++i)
		{
			if (_stricmp(ModuleVector[0][i].name.c_str(), name) == 0)
			{
				if (pos)
				{
					*pos = i;
					*DllVec = v;
				}

				return &ModuleVector[0][i];
			}
		}
	}

	return nullptr;
}