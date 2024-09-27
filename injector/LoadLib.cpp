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
		return PrintError("WriteProcessMemory[dll_buffer]");
	}

	const HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
	if (kernel32 == 0) return PrintError("GetModuleHandle");

	const FARPROC pLoadLib = GetProcAddress(kernel32, "LoadLibraryW");
	if (pLoadLib == NULL) return PrintError("GetProcAddress");

	if (!__CreateRemoteThread(process, pLoadLib, DllBuffer)) {
		PrintError("CreateRemoteThread[LoadLibInject]");
	}

	return true;
}