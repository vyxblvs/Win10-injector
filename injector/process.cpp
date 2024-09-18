#include "pch.h"
#include "mMap.hpp"
#include "process.hpp"
#include "injector.hpp"
#include "parsing.hpp"

HANDLE GetProcessHandle(const char* ProcessName)
{
	const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
	{
		PrintError("CreateToolhelp32Snapshot");
		return nullptr;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snap, &pe32))
	{
		PrintError("Process32First");
		CloseHandle(snap);
		return nullptr;
	}

	wchar_t ProcessNameW[MAX_PATH];
	mbstowcs_s(nullptr, ProcessNameW, ProcessName, MAX_PATH);

	do
	{
		if (_wcsicmp(ProcessNameW, pe32.szExeFile) == 0)
		{
			CloseHandle(snap);
			constexpr DWORD dwDesiredAccess = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
			const HANDLE process = OpenProcess(dwDesiredAccess, false, pe32.th32ProcessID);

			if (!process) {
				PrintError("OpenProcess");
				return nullptr;
			}

			USHORT ProcessMachine;
			USHORT NativeMachine;
			if (!IsWow64Process2(process, &ProcessMachine, &NativeMachine))
			{
				PrintError("IsWow64Process2");
				CloseHandle(process);
				return nullptr;
			}

			if (ProcessMachine == IMAGE_FILE_MACHINE_UNKNOWN)
			{
				PrintError("INVALID PROCESS ARCHITECTURE", false);
				CloseHandle(process);
				return nullptr;
			}

			return process;
		}

	} while (Process32Next(snap, &pe32));

	CloseHandle(snap);
	return nullptr;
}

bool GetLoadedModules(HANDLE process, std::vector<module_data>& buffer)
{
	DWORD sz;
	HMODULE handles[1024];
	if (!EnumProcessModules(process, handles, sizeof(handles), &sz))
	{
		PrintError("EnumProcessModules");
		return false;
	}

	sz /= sizeof(HMODULE);
	for (int i = 0; i < sz; ++i)
	{
		char path[MAX_PATH];
		if (!GetModuleFileNameExA(process, handles[i], path, MAX_PATH))
		{
			PrintError("GetModuleFileNameExA");
			return false;
		}

		buffer.push_back({});

		std::string& ModulePath = buffer.back().path;
		ModulePath = path;

		buffer.back().name = ModulePath.substr(ModulePath.find_last_of('\\') + 1);
	}
}