#pragma once

// Macros

#define GET_DATA_DIR(image, dir) image->NT_HEADERS->OptionalHeader.DataDirectory[dir]


// Forward Declarations

bool LoadDLL(const char* path, module_data* buffer);

bool GetDependencies(HANDLE process, module_data* target, std::vector<module_data>& buffer, std::vector<module_data>& LoadedModules, int it);