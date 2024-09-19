#include "pch.h"
#include "injector.hpp"
#include "LoadLib.hpp"

bool LoadLibInject(const HANDLE process, const char* dll)
{
	const auto PathSize = strlen(dll);

	void* DllBuffer = __VirtualAllocEx(process, PathSize, PAGE_READWRITE);
	if (DllBuffer == nullptr)
	{
		PrintError("VirtualAllocEx[LoadLibInject]");
		return false;
	}

	if (!WPM(process, DllBuffer, dll, PathSize))
	{
		PrintError("WriteProcessMemory[dll_buffer]");
		return false;
	}

	const HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
	if (!kernel32)
	{
		PrintError("GetModuleHandle");
		return false;
	}

	const FARPROC LoadLibAddr = GetProcAddress(kernel32, "LoadLibraryA");
	if (!LoadLibAddr)
	{
		PrintError("GetProcAddress");
		return false;
	}

	if (!__CreateRemoteThread(process, LoadLibAddr, DllBuffer))
	{
		PrintError("CreateRemoteThread[LoadLibInject]");
		return false;
	}

	return true;
}