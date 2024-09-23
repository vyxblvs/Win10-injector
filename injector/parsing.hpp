#pragma once

// ApiSetMap structs

struct API_SET_VALUE_ENTRY
{
	DWORD Flags;       // ignored; observed to be 0
	DWORD NameOffset;  // offset from start of map to name of importing module, in Unicode
	DWORD NameLength;  // size, in bytes, of name of importing module
	DWORD ValueOffset; // offset from start of map to name of host module, in Unicode
	DWORD ValueLength; // size, in bytes, of name of host module
};

struct NAMESPACE_HEADER
{
	DWORD SchemaExt;     // 5 or higher for recognition as schema extension in 10.0; observed to be 6 in 10.0
	DWORD MapSizeByte;   // size of map in bytes
	DWORD Flags;         // 0x01 bit set in ApiSetSchema if schema is sealed
	DWORD ApiSetCount;   // number of API Sets
	DWORD NsEntryOffset; // offset from start of map to array of namespace entries for API Sets
	DWORD HashOffset;    // offset from start of map to array of hash entries for API Sets
	DWORD Multiplier;    // multiplier to use when computing hash
};

struct API_SET_NAMESPACE_ENTRY
{
	DWORD Flags;           // 0x01 bit set in ApiSetSchema.dll if API Set is "sealed"
	DWORD ApiNameOffset;   // offset from start of map to name of API Set
	DWORD ApiNameSz;       // ignored; observed to be size, in bytes, of name of API Set
	DWORD ApiSubNameSz;    // size, in bytes, of name of API Set up to but not including last hyphen (api-ms-win-core-example-l1-1-1 -> api-ms-win-core-example-l1-1)
	DWORD HostEntryOffset; // offset from start of map to array of value entries for hosts
	DWORD HostCount;       // number of hosts
};

struct HASH_ENTRY // once im absolutely certain im resolving API sets the same as ntdll, ill start using these instead of string comparison
{
	DWORD ApiHash;  // hash of API Set's lower-case name up to but not including last hyphen
	DWORD ApiIndex; // index of API Set in array of namespace entries
};

// Macros

#define API_SET_SCHEMA_ENTRY_FLAGS_SEALED 1

#define pGetDataDir(data, dir) data->NT_HEADERS->OptionalHeader.DataDirectory[dir]

#define GetDataDir(data, dir) data.NT_HEADERS->OptionalHeader.DataDirectory[dir]

#define GetEP(data) data.NT_HEADERS->OptionalHeader.AddressOfEntryPoint

#define GetApiSetMap() NtCurrentTeb()->ProcessEnvironmentBlock->Reserved9[0]
 
// Forward Declarations

bool LoadDLL(const char* path, module_data* buffer);

bool GetDependencies(HANDLE process, module_data* target, std::vector<module_data>& buffer, std::vector<module_data>& LoadedModules, std::vector<API_DATA>& ApiData, int it);

bool ApplyRelocation(const module_data& ModuleData);

bool GetApiHost(module_data& api, std::vector<API_DATA>& ApiData, std::vector<module_data>& modules, std::vector<module_data>& LoadedModules);

bool ResolveImports(module_data& ModuleData, std::vector<module_data>& modules, std::vector<module_data>& LoadedModules, std::vector<API_DATA>& ApiData);