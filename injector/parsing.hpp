#pragma once

// Macros

#define PGET_DATA_DIR(data, dir) data->NT_HEADERS->OptionalHeader.DataDirectory[dir]

#define GET_DATA_DIR(data, dir) data.NT_HEADERS->OptionalHeader.DataDirectory[dir]

#define GET_ENTRY_POINT(data) data.NT_HEADERS->OptionalHeader.AddressOfEntryPoint


// Forward Declarations

bool LoadDLL(const char* path, module_data* buffer);

bool GetDependencies(HANDLE process, module_data* target, std::vector<module_data>& buffer, std::vector<module_data>& LoadedModules, int it);

bool ApplyRelocation(const module_data& ModuleData);

bool ResolveImports(module_data& ModuleData, std::vector<module_data>& modules, std::vector<module_data>& LoadedModules);