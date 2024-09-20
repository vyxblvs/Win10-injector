#pragma once

HANDLE GetProcessHandle(const char* ProcessName);

bool GetLoadedModules(HANDLE process, std::vector<MODULE_DATA>& buffer);

bool MapDLL(HANDLE process, MODULE_DATA& dll);

bool RunDllMain(HANDLE process, const MODULE_DATA& dll);