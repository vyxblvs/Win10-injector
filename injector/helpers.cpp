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

bool ResolveModulePath(HANDLE process, const std::string name, module_data* buffer)
{
	// Checking if the module is an API set, retrieving it from Windows\SysWOW64\downlevel if so
	// Once the injector is functional, the module location process will be updated to match the Windows DLL Loader

	if (IsApiSet(name))
	{
		const std::string APIpath = "C:\\Windows\\SysWOW64\\downlevel\\" + name;

		if (PathFileExistsA(APIpath.c_str()))
		{
			buffer->IsApiSet = true;
			return LoadDLL(APIpath.c_str(), buffer);
		}
		else
		{
			PrintError("FAILED TO LOCATE API SET");
			return false;
		}
	}

	// Checking Windows\SysWOW64

	std::string DllPath = "C:\\Windows\\SysWOW64\\" + name;
	if (PathFileExistsA(DllPath.c_str())) {
		return LoadDLL(DllPath.c_str(), buffer);
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
	DllPath += name;

	if (PathFileExistsA(DllPath.c_str())) {
		return LoadDLL(DllPath.c_str(), buffer);
	}

	PrintError("FAILED TO LOCATE MODULE");
	return false;
}

module_data* FindModule(const char* name, std::vector<module_data>& modules, std::vector<module_data>& LoadedModules, int* pos, int* ReturnedVec)
{
	for (UINT i = 0; i < modules.size(); ++i)
	{
		if (_stricmp(modules[i].name.c_str(), name) == 0)
		{
			if (pos)
			{
				*pos = i;
				*ReturnedVec = unloaded;
			}

			return &modules[i];
		}
	}

	for (UINT i = 0; i < LoadedModules.size(); ++i)
	{
		if (_stricmp(LoadedModules[i].name.c_str(), name) == 0)
		{
			if (pos)
			{
				*pos = i;
				*ReturnedVec = loaded;
			}

			return &LoadedModules[i];
		}
	}

	return nullptr;
}

std::string UnicodeToMultibyte(UNICODE_STRING& wstr)
{
	const USHORT len = wstr.Length / 2;

	std::string str(len + 1, '\0');
	wcstombs(str.data(), wstr.Buffer, len);

	return str;
}