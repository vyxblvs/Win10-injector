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
	DWORD SchemaExt;    // 5 or higher for recognition as schema extension in 10.0; observed to be 6 in 10.0
	DWORD MapSizeByte;  // size of map in bytes
	DWORD Flags;        // 0x01 bit set in ApiSetSchema if schema is sealed
	DWORD ApiSetCount;  // number of API Sets
	DWORD nsOffset;     // offset from start of map to array of namespace entries for API Sets
	DWORD HashOffset;   // offset from start of map to array of hash entries for API Sets
	DWORD Multiplier;   // multiplier to use when computing hash
};

struct NAMESPACE_ENTRY
{
	DWORD Flags;           // 0x01 bit set in ApiSetSchema.dll if API Set is "sealed"
	DWORD ApiNameOffset;   // offset from start of map to name of API Set
	DWORD ApiNameSz;       // ignored; observed to be size, in bytes, of name of API Set
	DWORD ApiSubNameSz;    // size, in bytes, of name of API Set up to but not including last hyphen (api-ms-win-core-example-l1-1-1 -> api-ms-win-core-example-l1-1)
	DWORD HostEntryOffset; // offset from start of map to array of value entries for hosts
	DWORD HostCount;       // number of hosts
};

struct HASH_ENTRY
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

bool LoadDLL(const char* path, MODULE_DATA* buffer);

bool GetDependencies(HANDLE process, MODULE_DATA* target, std::vector<MODULE_DATA>& buffer, std::vector<MODULE_DATA>& LoadedModules, std::vector<API_DATA>& ApiData, int it);

bool ApplyRelocation(const MODULE_DATA& ModuleData);

bool GetApiHosts(std::vector<API_DATA>& ApiData, std::vector<MODULE_DATA>& modules, std::vector<MODULE_DATA>& LoadedModules);

bool ResolveImports(MODULE_DATA& ModuleData, std::vector<MODULE_DATA>& modules, std::vector<MODULE_DATA>& LoadedModules, std::vector<API_DATA>& ApiData);