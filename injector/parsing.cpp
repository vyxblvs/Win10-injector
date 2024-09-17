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

	ModuleName.erase(ModuleName.size() - 4); // removing .dll from the string

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

bool LocateModule(HANDLE process, const std::string name, module_data& buffer)
{
	// Checking if the module is an API set, retrieving it from Windows\SysWOW64\downlevel if so
	// Once the injector is functional, the module location process will be updated to match the Windows DLL Loader

	if (IsAPIset(name))
	{
		const std::string APIpath = "C:\\Windows\\SysWOW64\\downlevel\\" + name;

		if (PathFileExistsA(APIpath.c_str())) 
		{
			buffer.ApiSet = true;
			return LoadDLL(APIpath.c_str(), &buffer);
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
		return LoadDLL(DllPath.c_str(), &buffer);
	}

	// Checking target process folder

	DWORD sz = 256;
	DllPath.clear();
	DllPath.resize(sz);
	if (!QueryFullProcessImageNameA(process, 0, DllPath.data(), &sz))
	{
		PrintError("QueryFullProcessImageNameA");
		return false;
	}
	
	DllPath.erase(DllPath.find_last_of('\\') + 1, DllPath.size());
	DllPath += name;

	if (PathFileExistsA(DllPath.c_str())) {
		return LoadDLL(DllPath.c_str(), &buffer);
	}

	PrintError("FAILED TO LOCATE MODULE");
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
		
		bool IsLoaded = false;
		for (auto LoadedModule : LoadedModules)
		{
			if (_stricmp(LoadedModule.name.c_str(), name) == 0) 
			{
				IsLoaded = true;
				break;
			}
		}
		if (IsLoaded) continue;

		buffer.push_back({});
		target = &buffer[it];
		if (!LocateModule(process, name, buffer.back())) {
			return false;
		}
	}

	return true;
}