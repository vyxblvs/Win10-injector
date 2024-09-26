#pragma once

HANDLE GetProcessHandle(const char* ProcessName);

bool GetLoadedModules(HANDLE process);

bool MapDLL(HANDLE process, DLL_DATA& dll);

bool RunDllMain(HANDLE process, const DLL_DATA& dll);