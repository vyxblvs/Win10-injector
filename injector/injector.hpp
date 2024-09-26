#pragma once

// Macros

#define ManualMap    0

#define _LoadLibrary 1

#define IGNORE_ERR   0

#define GET_LAST_ERR 1

#define RVA_CONVERSION_ERROR     2

#define __VirtualAllocEx(hProcess, dwSize, flProtect) VirtualAllocEx(hProcess, nullptr, dwSize, MEM_COMMIT | MEM_RESERVE, flProtect)

#define __CreateRemoteThread(hProcess, lpStartAddress, lpParameter) CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress), lpParameter, 0, nullptr)

#define WPM(hProcess, lpBaseAddress, lpBuffer, nSize) WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, nullptr)

// Forward declarations

int PrintError(const char* msg, int ErrorMode = GET_LAST_ERR, const char* rvaDesc = nullptr);

int PrintErrorRVA(const char* rvaDesc);