#include "pch.h"
#include "mMap.hpp"
#include "parsing.hpp"
#include "helpers.hpp"
#include "injector.hpp"

template <typename ret = const char*, typename ptr> auto ResolveRva(const DLL_DATA& image, DWORD RVA, ptr ModuleBase, bool MappedAddress = false) -> ret
{
	// RVA/VA explanations: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#general-concepts

	const IMAGE_SECTION_HEADER* sh = image.sections;

	for (int i = 0; i < image.NT_HEADERS->FileHeader.NumberOfSections; ++i)
	{
		auto* section = sh + i;
		const DWORD SectionVA = section->VirtualAddress;

		if (RVA >= SectionVA && RVA < SectionVA + section->SizeOfRawData)
		{
			const DWORD SectionOffset = MappedAddress ? SectionVA : section->PointerToRawData;
			const DWORD AddressOffset = SectionOffset + (RVA - SectionVA);

			return reinterpret_cast<ret>(reinterpret_cast<char*>(ModuleBase) + AddressOffset);
		}
	}

	return NULL;
}

bool LoadDll(const char* path, DLL_DATA* buffer)
{
	std::ifstream image(path, std::ios::binary | std::ios::ate);
	if (image.fail()) return PrintError("FAILED TO OPEN DLL", IGNORE_ERR_CODE);
	

	const auto sz = static_cast<size_t>(image.tellg());
	char* ImageBase = new char[sz];

	image.seekg(0, std::ios::beg);
	image.read(ImageBase, sz);
	image.close();

	std::string& DllPath = buffer->path;
	if (DllPath.empty()) // path/name already assigned if the module is loaded in the target process 
	{ 
		DllPath = path;
		buffer->name = DllPath.substr(DllPath.find_last_of('\\') + 1);
	}

	buffer->ImageBase  = reinterpret_cast<BYTE*>(ImageBase);
	buffer->NT_HEADERS = reinterpret_cast<IMAGE_NT_HEADERS32*>(ImageBase + *reinterpret_cast<DWORD*>(ImageBase + 0x3C));
	buffer->sections   = IMAGE_FIRST_SECTION(buffer->NT_HEADERS);

	return true;
}

bool GetDependencies(HANDLE process, DLL_DATA* target, int it)
{
	const IMAGE_DATA_DIRECTORY ImportTable = pGetDataDir(target, IMAGE_DIRECTORY_ENTRY_IMPORT);

	auto ImportDir = ResolveRva<const IMAGE_IMPORT_DESCRIPTOR*>(*target, ImportTable.VirtualAddress, target->ImageBase);
	if (!ImportDir) return PrintErrorRVA("ImportTable.VirtualAddress");
	
	for (int i = 0; ImportDir[i].Name; ++i)
	{
		const char* DllName = ResolveRva(*target, ImportDir[i].Name, target->ImageBase);
		if (!DllName) return PrintErrorRVA("ImportDir.Name");
		
		bool IsLoaded = false;
		for (DLL_DATA& dll : LoadedModules)
		{
			if (_stricmp(dll.name.c_str(), DllName) == 0) 
			{
				// If the module is already loaded in the target process but unloaded modules depend on it the image is to be loaded locally
				if (!dll.ImageBase && !LoadDll(dll.path.c_str(), &dll))
					return false;

				IsLoaded = true;
				break;
			}
		}
		if (IsLoaded || GetDllData(DllName)) continue;

		modules.push_back({});
		target = &modules[it];

		if (!GetModule(process, DllName, &modules.back())) 
			return false;

		if (modules.back().IsApiSet)
		{
			ApiSets.push_back({});
			modules.back().ApiDataPos = ApiSets.size() - 1;
		}
	}

	return true;
}

bool ApplyRelocation(const DLL_DATA& ModuleData)
{
	// .reloc explanation: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only

	const IMAGE_DATA_DIRECTORY pRelocTable = GetDataDir(ModuleData, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	auto RelocTable = ResolveRva<IMAGE_BASE_RELOCATION*>(ModuleData, pRelocTable.VirtualAddress, ModuleData.ImageBase);
	if (!RelocTable) return PrintErrorRVA("pRelocTable.VirtualAddress");
	
	const BYTE* RelocTableEnd = reinterpret_cast<BYTE*>(RelocTable) + pRelocTable.Size;
	const DWORD PreferredBase = ModuleData.NT_HEADERS->OptionalHeader.ImageBase;
	const DWORD AllocatedBase = ModuleData.RemoteBase;

	while (reinterpret_cast<BYTE*>(RelocTable) < RelocTableEnd)
	{
		auto entry = reinterpret_cast<RELOC_DATA*>(RelocTable) + 4;
		const size_t BlockSize = (RelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (size_t i = 0; i < BlockSize; ++i)
		{
			if (entry[i].Type == IMAGE_REL_BASED_ABSOLUTE) continue;

			const DWORD rva = static_cast<DWORD>(entry[i].Offset) + RelocTable->VirtualAddress;
			auto RelocAddress = ResolveRva<DWORD*>(ModuleData, rva, ModuleData.ImageBase);
			if (!RelocAddress) return PrintErrorRVA("RelocAddress");

			*RelocAddress = (*RelocAddress - PreferredBase) + AllocatedBase;
		}

		RelocTable = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(RelocTable) + RelocTable->SizeOfBlock);
	}

	return true;
}

bool ResolveApiHost(DLL_DATA& api)
{
	// Most of this function's code is from my other project, ApiView: https://github.com/islipnot/ApiView
	// This function specifically emulates ntdll's, ApiSetpSearchForApiSet

	static auto ApiSetMap = reinterpret_cast<API_SET_MAP*>(NtCurrentTeb()->ProcessEnvironmentBlock->Reserved9[0]);
	const auto dwApiSetMap = reinterpret_cast<DWORD_PTR>(ApiSetMap);

	const UINT ApiSubNameSz = api.name.size() - 6;
	std::wstring wApiName(ApiSubNameSz, '\0');
	mbstowcs(wApiName.data(), api.name.c_str(), ApiSubNameSz);

	// Hashing API name

	DWORD ApiHash = 0;

	for (UINT i = 0; i < ApiSubNameSz; ++i)
	{
		wchar_t ch = wApiName[i];

		// Assuring ch is lowercase. Cast prevents non-letters from fitting this case.
		if (static_cast<UINT16>(ch - 65) <= 25)
			ch += 32;

		ApiHash = ch + (ApiSetMap->Multiplier * ApiHash);
	}

	// Getting the offset of the API's corresponding HASH_TABLE entry

	int UpperMidIndex = 0;
	int LowerMidIndex = ApiSetMap->ApiSetCount - 1;
	
	DWORD HashEntryOffset = 0;
	DWORD HashTableOffset = ApiSetMap->HashOffset;
	
	while (true)
	{
		const int EntryIndex = (LowerMidIndex + UpperMidIndex) >> 1;
		HashEntryOffset = HashTableOffset + (sizeof(HASH_ENTRY) * EntryIndex);

		const DWORD LocatedHash = *reinterpret_cast<DWORD*>(dwApiSetMap + HashEntryOffset);

		if (ApiHash < LocatedHash)
		{
			LowerMidIndex = EntryIndex - 1;
		}
		else
		{
			if (ApiHash == LocatedHash) break;
			UpperMidIndex = EntryIndex + 1;
		}

		if (UpperMidIndex > LowerMidIndex) return false;
	}

	// Getting API's API_SET_NAMESPACE_ENTRY

	const ULONG HashApiIndex  = *reinterpret_cast<ULONG*>(reinterpret_cast<char*>(&ApiSetMap->MapSizeByte) + HashEntryOffset);
	const DWORD NsEntryOffset = ApiSetMap->NsEntryOffset + (sizeof(NAMESPACE_ENTRY) * HashApiIndex);
	const auto nsEntry        = reinterpret_cast<NAMESPACE_ENTRY*>(dwApiSetMap + NsEntryOffset);

	// Getting API's primary host name

	const auto HostEntry = reinterpret_cast<HOST_ENTRY*>(dwApiSetMap + nsEntry->HostEntryOffset);

	UNICODE_STRING HostName;
	HostName.MaximumLength = HostName.Length = static_cast<USHORT>(HostEntry->ValueLength);
	HostName.Buffer = reinterpret_cast<wchar_t*>(dwApiSetMap + HostEntry->ValueOffset);

	std::string MbHostName(HostName.Length >> 1, '\0');
	wcstombs(MbHostName.data(), HostName.Buffer, MbHostName.size());

	// Getting host's corresponding module_data struct

	API_DATA ApiBuffer;
	GetDllData(MbHostName.c_str(), &ApiBuffer.HostPos, &ApiBuffer.HostVec);

	ApiSets[api.ApiDataPos] = ApiBuffer;
	return true;
}

DWORD_PTR ResolveExportAddress(HANDLE process, const char* TargetExport, DLL_DATA& ModuleData)
{
	BYTE* ImageBase = ModuleData.ImageBase;
	const IMAGE_DATA_DIRECTORY ExportDir = GetDataDir(ModuleData, IMAGE_DIRECTORY_ENTRY_EXPORT);

	auto ExportTable = ResolveRva<const IMAGE_EXPORT_DIRECTORY*>(ModuleData, ExportDir.VirtualAddress, ImageBase);
	if (!ExportTable) return PrintErrorRVA("ExportDir.VirtualAddress");
	
	auto NameTablePtr = ResolveRva<DWORD*>(ModuleData, ExportTable->AddressOfNames, ImageBase);
	if (!NameTablePtr) return PrintErrorRVA("ExportTable->AddressOfNames");

	auto OrdinalTable = ResolveRva<WORD*>(ModuleData, ExportTable->AddressOfNameOrdinals, ModuleData.ImageBase);
	if (!OrdinalTable) return PrintErrorRVA("ExportTable->AddressOfNameOrdinals");
	
	auto EAT = ResolveRva<DWORD*>(ModuleData, ExportTable->AddressOfFunctions, ModuleData.ImageBase);
	if (!EAT) return PrintErrorRVA("ExportTable->AddressOfFunctions");
	
	for (ULONG i = 0; i < ExportTable->NumberOfFunctions; ++i)
	{
		const char* ExportName = ResolveRva(ModuleData, NameTablePtr[i], ImageBase);
		if (!ExportName) return PrintErrorRVA("NameTable[i]");	

		if (_stricmp(TargetExport, ExportName) == 0)
		{
			const DWORD FnRva = EAT[static_cast<DWORD>(OrdinalTable[i])];

			// If fnAddress is within the export section, its a forwarder
			if (FnRva >= ExportDir.VirtualAddress && FnRva < ExportDir.VirtualAddress + ExportDir.Size)
			{
				const char* ForwarderName = ResolveRva(ModuleData, FnRva, ModuleData.ImageBase);
				if (!ForwarderName) return PrintErrorRVA("EAT[OrdinalTable[i]]<FORWARDER>");
				
				std::string HostName, FnName = ForwarderName;
				HostName = FnName.substr(0, FnName.find_first_of('.')) + ".dll";
				FnName.erase(0, FnName.find_last_of('.') + 1);

				DLL_DATA* ApiHost = GetDllData(HostName.c_str());
				if (ApiHost == nullptr)
				{
					modules.push_back({});

					if (!GetModule(process, HostName, &modules.back())) {
						return NULL;
					}

					ApiHost = &modules.back();
					if (ApiHost->IsApiSet)
					{
						ApiSets.push_back({});
						ApiHost->ApiDataPos = ApiSets.size() - 1;
						ResolveApiHost(modules.back());
					}
				}

				if (ApiHost->IsApiSet)
				{
					const API_DATA& ApiSet = ApiSets[ApiHost->ApiDataPos];

					if (ApiSet.HostVec == loaded) ApiHost = &LoadedModules[ApiSet.HostPos];
					else ApiHost = &modules[ApiSet.HostPos];
				}
				if (!ApiHost->ImageBase && !LoadDll(ApiHost->path.c_str(), ApiHost)) {
					return NULL;
				}

				return ResolveExportAddress(process, FnName.c_str(), *ApiHost);
			}

			return ResolveRva<DWORD_PTR>(ModuleData, FnRva, ModuleData.RemoteBase, true);
		}
	}
	
	return PrintError("FAILED TO RESOLVE EXPORT ADDRESS", IGNORE_ERR_CODE);
}

bool ResolveImports(HANDLE process, DLL_DATA* ModuleData, int it)
{
	const IMAGE_DATA_DIRECTORY ImportTable = pGetDataDir(ModuleData, IMAGE_DIRECTORY_ENTRY_IMPORT);
	auto ImportDir = ResolveRva<const IMAGE_IMPORT_DESCRIPTOR*>(*ModuleData, ImportTable.VirtualAddress, ModuleData->ImageBase);
	if (ImportDir == nullptr) return PrintErrorRVA("ImportTable.VirtualAddress");
	
	for (int i = 0; ImportDir[i].Name; ++i)
	{
		const char* DllName = ResolveRva(*ModuleData, ImportDir[i].Name, ModuleData->ImageBase);

		DLL_DATA* ImportedModule = GetDllData(DllName);
		if (!ImportedModule) return PrintError("FAILED TO LOCATE MODULE[ResolveImports]", IGNORE_ERR_CODE);
		
		// Import Address Table
		auto IAT = ResolveRva<IMAGE_THUNK_DATA32*>(*ModuleData, ImportDir[i].FirstThunk, ModuleData->ImageBase);
		if (!IAT) return PrintErrorRVA("ImportDir[i].FirstThunk");

		// Import Lookup Table
		auto ILT = ResolveRva<const IMAGE_THUNK_DATA32*>(*ModuleData, ImportDir[i].Characteristics, ModuleData->ImageBase);
		if (!ILT) return PrintErrorRVA("ImportDir[i].Characteristics"); 
		
		for (int fn = 0; ILT[fn].u1.Function; ++fn)
		{
			auto ImportByName = ResolveRva<const IMAGE_IMPORT_BY_NAME*>(*ModuleData, ILT[fn].u1.AddressOfData, ModuleData->ImageBase);
			if (!ImportByName) return PrintError("ILT[fn].u1.AddressOfData");
			
			const DWORD_PTR FnAddress = ResolveExportAddress(process, ImportByName->Name, *ImportedModule);
			if (!FnAddress) return false;

			IAT[fn].u1.AddressOfData = FnAddress;
			ModuleData = &modules[it];
		}
	}

	return true;
}