#include "pch.h"
#include "injector.hpp"
#include "LoadLib.hpp"

bool LoadLibInject(const HANDLE process, const wchar_t* DllPath)
{
	const size_t PathSize = wcslen(DllPath);

	void* DllBuffer = __VirtualAllocEx(process, PathSize, PAGE_READWRITE);
	if (DllBuffer == nullptr) {
		return PrintError("VirtualAllocEx[LoadLibInject]");
	}

	if (!WPM(process, DllBuffer, DllPath, PathSize)) {
		PrintError("WriteProcessMemory[dll_buffer]");
	}

	const HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
	if (!kernel32) {
		return PrintError("GetModuleHandle");
	}

	const FARPROC LoadLibAddr = GetProcAddress(kernel32, "LoadLibraryW");
	if (!LoadLibAddr) {
		PrintError("GetProcAddress");
	}

	if (!__CreateRemoteThread(process, LoadLibAddr, DllBuffer)) {
		PrintError("CreateRemoteThread[LoadLibInject]");
	}

	return true;
}