#pragma once

#define GET_DATA_DIR(image, dir) image.NT_HEADERS->OptionalHeader.DataDirectory[dir]

bool LoadDLL(const char* path, module_data* buffer);

bool ApplyRelocation(const module_data& target);

bool GetDependencies(const module_data& target, std::vector<module_data>& buffer);