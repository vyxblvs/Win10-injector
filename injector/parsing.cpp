#include "pch.h"
#include "injector.hpp"
#include "mMap.hpp"
#include "parsing.hpp"

template <typename ret> auto ConvertRVA(const module_data& image, DWORD RVA, BYTE* ModuleBase)->ret
{
	// RVA/VA explanations: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#general-concepts

	const IMAGE_SECTION_HEADER* sh = image.sections;

	for (int i = 0; i < image.NT_HEADERS->FileHeader.NumberOfSections; ++i)
	{
		const DWORD SectionVA = sh[i].VirtualAddress;

		if (RVA >= SectionVA && RVA < (SectionVA + sh[i].SizeOfRawData))
		{
			const DWORD offset = sh[i].PointerToRawData + (RVA - SectionVA);
			return reinterpret_cast<ret>(ModuleBase + offset);
		}
	}

	return NULL;
}

bool LoadDLL(const char* path, module_data* buffer)
{
	const LOADED_IMAGE* image = ImageLoad(path, nullptr);
	if (!image)
	{
		PrintError("ImageLoad");
		return false;
	}

	std::string& sPath = buffer->path;
	sPath = path;

	buffer->name       = sPath.substr(sPath.find_last_of('\\') + 1);
	buffer->ImageBase  = image->MappedAddress;
	buffer->NT_HEADERS = image->FileHeader;
	buffer->sections   = IMAGE_FIRST_SECTION(image->FileHeader);

	return true;
}

bool IsAPIset(std::string ModuleName)
{
	// API Set naming conventions specified at https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets

	std::string NameStart = ModuleName.substr(0, 4);
	if (_stricmp(NameStart.c_str(), "api-") != 0 && _stricmp(NameStart.c_str(), "ext-") != 0) {
		return false;
	}

	ModuleName.erase(0, ModuleName.size() - 6);
	if (ModuleName[0] != 'l' && ModuleName[0] != 'L') {
		return false;
	}

	for (int i = 1; i < 6; ++i)
	{
		if (i % 2 == 0)
		{
			if (ModuleName[i] != '-') {
				return false;
			}
		}
		else if (!std::isdigit(static_cast<BYTE>(ModuleName[i]))) {
			return false;
		}
	}

	return true;
}

bool LocateModule(HANDLE process, std::string name, module_data& buffer)
{
	// Checking known DLLs

	HKEY key;
	if (RegOpenKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", &key))
	{
		PrintError("RegOpenKey", false);
		return false;
	}

	DWORD index = 0;
	char DllName[256];
	DWORD NameSz;
	BYTE data[256];
	DWORD DataSz;

	name.erase(name.size() - 4, name.size());

	while (true)
	{
		NameSz = sizeof(DllName);
		DataSz = sizeof(data);
		LONG result = RegEnumValueA(key, index, DllName, &NameSz, NULL, NULL, data, &DataSz);

		if (result == ERROR_NO_MORE_ITEMS) {
			break;
		}
		else if (result == ERROR_SUCCESS)
		{
			if (_stricmp(name.c_str(), DllName) == 0)
			{
				name.insert(0, "C:\\Windows\\SysWOW64\\"); // need to get windows directory at runtime instead
				name += ".dll";
				return LoadDLL(name.c_str(), &buffer);
			}

			++index;
		}
		else
		{
			PrintError("RegEnumValue", false);
			return false;
		}
	}

	// Checking target process folder

	name += ".dll";

	std::string ProcessDir(256, 0);
	if (!QueryFullProcessImageNameA(process, 0, ProcessDir.data(), &DataSz))
	{
		PrintError("QueryFullProcessImageNameA");
		return false;
	}
	
	ProcessDir.erase(ProcessDir.find_last_of('\\') + 1, ProcessDir.size());
	ProcessDir += name;

	if (PathFileExistsA(ProcessDir.c_str())) {
		return LoadDLL(ProcessDir.c_str(), &buffer);
	}

	
	return false;
}

bool GetDependencies(HANDLE process, module_data* target, std::vector<module_data>& buffer, std::vector<module_data>& LoadedModules, int it)
{
	const IMAGE_DATA_DIRECTORY ImportTable = GET_DATA_DIR(target, IMAGE_DIRECTORY_ENTRY_IMPORT);
	const auto ImportDir = ConvertRVA<IMAGE_IMPORT_DESCRIPTOR*>(*target, ImportTable.VirtualAddress, target->ImageBase);
	if (!ImportDir)
	{
		PrintError("FAILED TO CONVERT RVA[ImportTable.VirtualAddress]");
		return false;
	}

	for (int i = 0; ImportDir[i].Name != NULL; ++i)
	{
		auto name = ConvertRVA<const char*>(*target, ImportDir[i].Name, target->ImageBase);
		
		for (auto LoadedModule : LoadedModules)
		{
			if (_stricmp(LoadedModule.name.c_str(), name) == 0) {
				continue; // module is already loaded in target process
			}
		}

		buffer.push_back({});
		target = &buffer[it];
		if (!LocateModule(process, name, buffer.back())) {
			return false;
		}
	}

	return true;
}