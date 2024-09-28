#pragma once

HANDLE GetProcessHandle(const wchar_t* ProcessName);

bool LoadLibInject(const HANDLE process, const wchar_t* DllPath);

bool GetLoadedModules(HANDLE process);

bool MapDLL(HANDLE process, DLL_DATA& dll);

bool RunDllMain(HANDLE process, const DLL_DATA& dll);