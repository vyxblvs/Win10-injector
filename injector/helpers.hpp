#pragma once

bool ResolveModulePath(HANDLE process, const std::string name, module_data* buffer);

module_data* FindModule(const char* name, std::vector<module_data>& modules, std::vector<module_data>& LoadedModules, int* pos = nullptr, int* ReturnedVec = nullptr);

std::string UnicodeToMultibyte(UNICODE_STRING& wstr);