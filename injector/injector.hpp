#pragma once

// Enums

enum InjectionMethod
{
	ManualMap = 0,
	LoadLib   = 1,
};

enum ErrorFlags
{
	IGNORE_ERR_CODE = 0,
	GET_LAST_ERR    = 1,
	RVA_CONVERT_ERR = 2
};

// Macros

#define __VirtualAllocEx(hProcess, dwSize, flProtect) VirtualAllocEx(hProcess, nullptr, dwSize, MEM_COMMIT | MEM_RESERVE, flProtect)

#define __CreateRemoteThread(hProcess, lpStartAddress, lpParameter) CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress), lpParameter, 0, nullptr)

#define WPM(hProcess, lpBaseAddress, lpBuffer, nSize) WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, nullptr)

// Forward declarations

int PrintError(const char* msg, ErrorFlags ErrorMode = GET_LAST_ERR, const char* rvaDesc = nullptr);

int PrintErrorRVA(const char* rvaDesc);