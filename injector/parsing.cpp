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
	std::ifstream image(path, std::ios::binary | std::ios::ate);
	if (image.fail())
	{
		PrintError("FAILED TO OPEN DLL", false);
		return false;
	}

	const auto sz = static_cast<size_t>(image.tellg());
	char* ImageBase = new char[sz];

	image.seekg(0, std::ios::beg);
	image.read(ImageBase, sz);
	image.close();

	std::string& sPath = buffer->path;
	if (sPath.empty()) // path/name already assigned if the module is loaded in the target process 
	{ 
		sPath = path;
		buffer->name = sPath.substr(sPath.find_last_of('\\') + 1);
	}

	buffer->ImageBase  = reinterpret_cast<BYTE*>(ImageBase);
	buffer->NT_HEADERS = reinterpret_cast<IMAGE_NT_HEADERS32*>(ImageBase + *reinterpret_cast<DWORD*>(ImageBase + 0x3C));
	buffer->sections   = IMAGE_FIRST_SECTION(buffer->NT_HEADERS);

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
	const IMAGE_DATA_DIRECTORY ImportTable = PGET_DATA_DIR(target, IMAGE_DIRECTORY_ENTRY_IMPORT);
	const auto ImportDir = ConvertRVA<IMAGE_IMPORT_DESCRIPTOR*>(*target, ImportTable.VirtualAddress, target->ImageBase);
	if (!ImportDir)
	{
		PrintError("FAILED TO CONVERT RVA[ImportTable.VirtualAddress]", false);
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
				/* If the module is already loaded in the target process but unloaded modules depend on it -
				   the image is to be loaded locally */

				if (LoadedModule.ImageBase == nullptr && !LoadDLL(LoadedModule.path.c_str(), &LoadedModule)) {
					return false;
				}

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

bool ApplyRelocation(const module_data& ModuleData)
{
	// .reloc explanation: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only

	const IMAGE_DATA_DIRECTORY pRelocTable = GET_DATA_DIR(ModuleData, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	auto RelocTable = ConvertRVA<IMAGE_BASE_RELOCATION*>(ModuleData, pRelocTable.VirtualAddress, ModuleData.ImageBase);
	if (!RelocTable) 
	{
		PrintError("FAILED TO CONVERT RVA[pRelocTable.VirtualAddress]", false);
		return false;
	}

	BYTE* RelocTableEnd = reinterpret_cast<BYTE*>(RelocTable) + pRelocTable.Size;
	DWORD PreferredBase = ModuleData.NT_HEADERS->OptionalHeader.ImageBase;
	DWORD AllocatedBase = ModuleData.RemoteBase;

	while (reinterpret_cast<BYTE*>(RelocTable) < RelocTableEnd)
	{
		auto entry = reinterpret_cast<const WORD*>(RelocTable) + 4;
		const size_t BlockSize = (RelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (size_t i = 0; i < BlockSize; ++i)
		{
			const DWORD RVA = (entry[i] % 0x1000) + RelocTable->VirtualAddress;
			auto RelocAddress = ConvertRVA<DWORD*>(ModuleData, RVA, ModuleData.ImageBase);
			if (!RelocAddress)
			{
				PrintError("FAILED TO CONVERT RVA[RelocAddress]", false);
				return false;
			}

			*RelocAddress = (*RelocAddress - PreferredBase) + AllocatedBase;
		}

		RelocTable = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(RelocTable) + RelocTable->SizeOfBlock);
	}

	return true;
}