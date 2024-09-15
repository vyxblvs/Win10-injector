#include "pch.h"
#include "injector.hpp"
#include "manual_map.hpp"
#include "file_parsing.hpp"

// Gets file offset from an RVA and adds it to the specified base
template <typename ret> auto ConvertRVA(const module_data& image, DWORD RVA, BYTE* ModuleBase)->ret
{
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

	buffer->ImageBase  = image->MappedAddress;
	buffer->NT_HEADERS = image->FileHeader;
	buffer->sections   = IMAGE_FIRST_SECTION(image->FileHeader);

	return true;
}

bool ApplyRelocation(const module_data& target)
{
	
	 
	return true;
}

bool GetDependencies(const module_data& target, std::vector<module_data>& buffer)
{
	const IMAGE_DATA_DIRECTORY ImportTable = GET_DATA_DIR(target, IMAGE_DIRECTORY_ENTRY_IMPORT);
	const auto ImportDir = ConvertRVA<IMAGE_IMPORT_DESCRIPTOR*>(target, ImportTable.VirtualAddress, target.ImageBase);
	if (!ImportDir)
	{
		PrintError("FAILED TO CONVERT RVA[ImportTable.VirtualAddress]");
		return false;
	}

	for (int i = 0; ImportDir[i].Name != NULL; ++i)
	{
		auto name = ConvertRVA<const char*>(target, ImportDir[i].Name, target.ImageBase);
		
	}

	return true;
}