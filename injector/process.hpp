#pragma once

HANDLE GetProcessHandle(const char* ProcessName);

bool GetLoadedModules(HANDLE process, std::vector<module_data>& buffer);

bool MapDLL(HANDLE process, module_data& dll);

bool RunDllMain(HANDLE process, const module_data& dll);