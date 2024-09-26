#include "pch.h"
#include "mMap.hpp"
#include "parsing.hpp"
#include "helpers.hpp"
#include "injector.hpp"

bool IsApiSet(std::string ModuleName)
{
	// API Set naming conventions specified at https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets

	if (ModuleName.substr(ModuleName.size() - 4) == ".dll")
		ModuleName.erase(ModuleName.size() - 4);

	std::string NameStart = ModuleName.substr(0, 4);
	if (_stricmp(NameStart.c_str(), "api-") != 0 && _stricmp(NameStart.c_str(), "ext-") != 0)
		return false;

	ModuleName.erase(0, ModuleName.size() - 6);
	if (ModuleName[0] != 'l' && ModuleName[0] != 'L')
		return false;

	for (int i = 1; i < 6; ++i)
	{
		if (i % 2 == 0)
		{
			if (ModuleName[i] != '-')
				return false;
		}

		else if (!std::isdigit(static_cast<BYTE>(ModuleName[i])))
			return false;
	}

	return true;
}

bool GetModule(HANDLE process, const std::string DllName, DLL_DATA* buffer)
{
	// Checking if the module is an API set, retrieving it from Windows\SysWOW64\downlevel if so
	// Once the injector is functional, the module location process will be updated to match the Windows DLL Loader

#pragma warning(push)
#pragma warning(disable : 6031)

	std::string SysWOW(MAX_PATH, 0);
	const UINT WinDirSz = GetWindowsDirectoryA(SysWOW.data(), MAX_PATH);
	SysWOW.resize(WinDirSz);
	SysWOW += "\\SysWOW64\\";

#pragma warning(pop)

	if (IsApiSet(DllName))
	{
		const std::string APIpath = SysWOW + "downlevel\\" + DllName;

		if (PathFileExistsA(APIpath.c_str()))
		{
			buffer->IsApiSet = true;
			return LoadDll(APIpath.c_str(), buffer);
		}
		else
		{
			PrintError("FAILED TO LOCATE API SET");
			return false;
		}
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
	if (QueryFullProcessImageNameA(process, 0, DllPath.data(), &sz) == 0)
	{
		PrintError("QueryFullProcessImageNameA");
		return false;
	}

	DllPath.erase(DllPath.find_last_of('\\') + 1, DllPath.size());
	DllPath += DllName;

	if (PathFileExistsA(DllPath.c_str())) {
		return LoadDll(DllPath.c_str(), buffer);
	}

	PrintError("FAILED TO LOCATE MODULE");
	return false;
}

DLL_DATA* GetDllData(const char* name, int* pos, bool* ReturnedVec)
{
	std::vector<DLL_DATA>* ModuleVector = &modules;

CheckVector:

	for (UINT i = 0; i < ModuleVector->size(); ++i)
	{
		if (_stricmp(ModuleVector[0][i].name.c_str(), name) == 0)
		{
			if (pos)
			{
				*pos = i;
				*ReturnedVec = unloaded;
			}

			return &ModuleVector[0][i];
		}
	}

	if (ModuleVector == &LoadedModules) return nullptr;
	else { ModuleVector = &LoadedModules; goto CheckVector; }
}

std::string UnicodeToMultibyte(UNICODE_STRING& wstr)
{
	const USHORT len = wstr.Length / 2;
	std::string str(len + 1, '\0');

	wcstombs(str.data(), wstr.Buffer, len);

	return str;
}