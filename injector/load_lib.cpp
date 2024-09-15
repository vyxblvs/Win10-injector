#include "pch.h"
#include "injector.hpp"
#include "load_lib.hpp"

bool LoadLibInject(const HANDLE process, const char* dll)
{
	const auto PathSize = strlen(dll);

	void* DllBuffer = VirtualAllocEx(process, nullptr, PathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (DllBuffer == nullptr)
	{
		PrintError("VirtualAllocEx[LoadLibInject]");
		return false;
	}

	if (!WriteProcessMemory(process, DllBuffer, dll, PathSize, nullptr))
	{
		PrintError("WriteProcessMemory[dll_buffer]");
		return false;
	}

	const HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
	const FARPROC LoadLibAddr = GetProcAddress(kernel32, "LoadLibraryA");

	if (!CreateRemoteThread(process, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibAddr), DllBuffer, 0, nullptr))
	{
		PrintError("CreateRemoteThread[LoadLibInject]");
		return false;
	}

	return true;
}