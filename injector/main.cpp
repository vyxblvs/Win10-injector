#include "pch.h"
#include "injector.hpp"
#include "load_lib.hpp"
#include "mMap.hpp"

void PrintError(const char* msg, int ErrorMode, const char* rvaDesc)
{
	if (ErrorMode == RVA_FAIL) {
		std::cerr << "ERROR: FAILED TO CONVERT RVA (" << rvaDesc << ")\n";
	}
	else if (ErrorMode == GET_LAST_ERR) {
		std::cerr << "ERROR: " << msg << " (" << GetLastError() << ")\n";
	}
	else {
		std::cerr << "ERROR: " << msg << '\n';
	}
}

void PrintErrorRVA(const char* rvaDesc) 
{ 
	PrintError(nullptr, RVA_FAIL, rvaDesc); 
}

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

			if (process == NULL) {
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

// THIS INJECTOR IS MADE FOR x86 PROCESSES/DLLS

// Argument format: injector.exe [process_name.exe] [dll_path.dll] [injection method]
// Injection method defaults to LoadLibraryA if one is not specified
// Arguments are NOT case sensitive

int main(int argc, char* argv[])
{
	const char* ProcessName;
	const char* DllPath;
	bool method = _LoadLibrary;

	// Checking arguments
	if (argc <= 2)
	{
		PrintError("Invalid Arguments", false);
		return 1;
	}
	else
	{
		ProcessName = argv[1];
		DllPath = argv[2];

		if (argc >= 4) 
		{
			if (_stricmp(argv[3], "ManualMap") == 0) {
				method = ManualMap;
			}
			else if (_stricmp(argv[3], "LoadLibraryA") != 0)
			{
				// Does not default to LoadLibraryA in this case to avoid unwanted injection
				PrintError("Invalid injection method", false);
				return 1;
			}
		}
	}

	const HANDLE process = GetProcessHandle(ProcessName);
	if (!process) {
		return 1;
	}

	if (method == _LoadLibrary && !LoadLibInject(process, DllPath))
	{
		PrintError("LoadLibraryA injection failed\n", false);
		return 1;
	}
	else if (method == ManualMap && !ManualMapDll(process, DllPath))
	{
		PrintError("Manual Mapping injection failed\n", false);
		return 1;
	}

	std::cout << "DLL Successfully Injected!\n";
	return 0;
}