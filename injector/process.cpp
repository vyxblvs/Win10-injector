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

	wchar_t wProcessName[MAX_PATH];
	mbstowcs_s(nullptr, wProcessName, ProcessName, MAX_PATH);

	do
	{
		if (_wcsicmp(wProcessName, pe32.szExeFile) == 0)
		{
			CloseHandle(snap);

			// PROCESS_QUERY_LIMITED_INFORMATION is requested to check if the process is running under WOW64.
			// If for whatever reason you want to avoid this access right, you can remove it aswell as the WOW64 check without issue.
			
			constexpr DWORD dwDesiredAccess = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION;
			const HANDLE process = OpenProcess(dwDesiredAccess, false, pe32.th32ProcessID);

			if (!process) 
			{
				PrintError("OpenProcess");
				return nullptr;
			}

			BOOL Wow64Process;
			IsWow64Process(process, &Wow64Process);

			if (Wow64Process == FALSE)
			{
				PrintError("INVALID PROCESS ARCHITECTURE", IGNORE_ERR);
				CloseHandle(process);
				return nullptr;
			}

			return process;
		}

	} while (Process32Next(snap, &pe32));


	PrintError("FAILED TO LOCATE PROCESS", IGNORE_ERR);
	CloseHandle(snap);
	return nullptr;
}

bool GetLoadedModules(HANDLE process)
{
	DWORD sz;
	HMODULE handles[1024];
	if (!EnumProcessModules(process, handles, sizeof(handles), &sz))
	{
		PrintError("EnumProcessModules");
		return false;
	}

	sz /= sizeof(HMODULE);
	for (ULONG i = 0; i < sz; ++i)
	{
		char path[MAX_PATH];
		if (!GetModuleFileNameExA(process, handles[i], path, MAX_PATH))
		{
			PrintError("GetModuleFileNameExA");
			return false;
		}

		LoadedModules.push_back({});
		DLL_DATA& dll = LoadedModules.back();

		std::string& ModulePath = dll.path;
		ModulePath = path;

		dll.name = ModulePath.substr(ModulePath.find_last_of('\\') + 1);
		dll.pRemoteBase = handles[i];
	}

	return true;
}

bool MapDLL(HANDLE process, DLL_DATA& dll)
{
	const IMAGE_SECTION_HEADER* sh = dll.sections;

	// Mapping PE headers
	if (!WPM(process, dll.pRemoteBase, dll.ImageBase, dll.NT_HEADERS->OptionalHeader.SizeOfHeaders))
	{
		PrintError("FAILED TO MAP PE HEADERS");
		return false;
	}

	// Mapping sections
	for (WORD i = 0; i < dll.NT_HEADERS->FileHeader.NumberOfSections; ++i)
	{
		auto& section = sh[i];

		void* pSection = dll.ImageBase + section.PointerToRawData;
		void* SectionBuffer = static_cast<BYTE*>(dll.pRemoteBase) + section.VirtualAddress;
		SIZE_T SizeOfRawData = section.SizeOfRawData;

		if (SizeOfRawData && !WPM(process, SectionBuffer, pSection, SizeOfRawData))
		{
			PrintError("FAILED TO MAP SECTION");
			return false;
		}
	}

	return true; 
}

bool RunDllMain(HANDLE process, const DLL_DATA& dll)
{
	BYTE shellcode[] =
	{
		0x6A, 0x00,       // push 0 (lpvReserved)
		0x6A, 0x01,       // push 1 (fdwReason - DLL_PROCESS_ATTACH)
		0x68, 0, 0, 0, 0, // push 0 (hinstDLL)
		0xE8, 0, 0, 0, 0, // call 0 (DllMain)
		0xC2, 0x04, 0x00  // ret 4
	};

	void* pShellcode = __VirtualAllocEx(process, sizeof(shellcode), PAGE_EXECUTE_READWRITE);
	if (pShellcode == NULL)
	{
		PrintError("VirtualAllocEx[RunDllMain]");
		return false;
	}

	const DWORD_PTR EntryPoint = GetEP(dll) + dll.RemoteBase;
	*reinterpret_cast<DWORD*>(shellcode + 5) = dll.RemoteBase; // hinstDLL
	*reinterpret_cast<DWORD*>(shellcode + 10) = EntryPoint - (reinterpret_cast<DWORD>(pShellcode) + 14); // EP

	if (WPM(process, pShellcode, shellcode, sizeof(shellcode)) == 0)
	{
		PrintError("WriteProcessMemory[RunDllMain]");
		return false;
	}

	if (__CreateRemoteThread(process, pShellcode, nullptr) == 0)
	{
		PrintError("CreateRemoteThread[RunDllMain]");
		return false;
	}
	
	return true;
}