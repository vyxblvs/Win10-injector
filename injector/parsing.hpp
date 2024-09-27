#pragma once

// ApiSetMap structs

typedef struct API_SET_VALUE_ENTRY
{
	DWORD Flags;       // ignored; observed to be 0
	DWORD NameOffset;  // offset from start of map to name of importing module, in Unicode
	DWORD NameLength;  // size, in bytes, of name of importing module
	DWORD ValueOffset; // offset from start of map to name of host module, in Unicode
	DWORD ValueLength; // size, in bytes, of name of host module
} VALUE_ENTRY, HOST_ENTRY;

typedef struct NAMESPACE_HEADER
{
	DWORD SchemaExt;     // 5 or higher for recognition as schema extension in 10.0; observed to be 6 in 10.0
	DWORD MapSizeByte;   // size of map in bytes
	DWORD Flags;         // 0x01 bit set in ApiSetSchema if schema is sealed
	DWORD ApiSetCount;   // number of API Sets
	DWORD NsEntryOffset; // offset from start of map to array of namespace entries for API Sets
	DWORD HashOffset;    // offset from start of map to array of hash entries for API Sets
	DWORD Multiplier;    // multiplier to use when computing hash
} API_SET_MAP;

typedef struct API_SET_NAMESPACE_ENTRY
{
	DWORD Flags;           // 0x01 bit set in ApiSetSchema.dll if API Set is "sealed"
	DWORD ApiNameOffset;   // offset from start of map to name of API Set
	DWORD ApiNameSz;       // ignored; observed to be size, in bytes, of name of API Set
	DWORD ApiSubNameSz;    // size, in bytes, of name of API Set up to but not including last hyphen
	DWORD HostEntryOffset; // offset from start of map to array of value entries for hosts
	DWORD HostCount;       // number of hosts
} NAMESPACE_ENTRY;

struct HASH_ENTRY
{
	DWORD ApiHash;  // hash of API Set's lower-case name up to but not including last hyphen
	DWORD ApiIndex; // index of API Set in array of namespace entries
};

// Macros

#define pGetDataDir(data, dir) data->NT_HEADERS->OptionalHeader.DataDirectory[dir]

#define GetDataDir(data, dir) data.NT_HEADERS->OptionalHeader.DataDirectory[dir]

#define GetEP(data) data.NT_HEADERS->OptionalHeader.AddressOfEntryPoint
 
// Forward Declarations

bool LoadDll(const char* path, DLL_DATA* buffer);

bool GetDependencies(HANDLE process, DLL_DATA* target, int it);

bool ApplyRelocation(const DLL_DATA& ModuleData);

bool ResolveApiHost(DLL_DATA& api);

bool ResolveImports(HANDLE process, DLL_DATA* ModuleData, int it);