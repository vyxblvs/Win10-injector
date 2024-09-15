#include "pch.h"
#include "injector.hpp"
#include "manual_map.hpp"
#include "file_parsing.hpp"

// Return value = size of image in memory
size_t LoadDLL(const char* path, module_data* buffer)
{
	std::ifstream dll(path, std::ios::binary | std::ios::ate);
	if (dll.fail())
	{
		PrintError("FAILED TO OPEN DLL", false);
		return 0;
	}
	
	const size_t sz = static_cast<size_t>(dll.tellg());
	char* ImageBase = new char[sz];

	dll.seekg(0, std::ios::beg);
	dll.read(ImageBase, sz);
	dll.close();

	buffer->ImageBase = ImageBase;
	buffer->NT_HEADERS = reinterpret_cast<PIMAGE_NT_HEADERS32>(ImageBase + *reinterpret_cast<DWORD32*>(ImageBase + 0x3C));

	std::cout << buffer->NT_HEADERS->FileHeader.NumberOfSections << '\n';

	return sz;
}