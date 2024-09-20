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

bool GetLoadedModules(HANDLE process, std::vector<MODULE_DATA>& buffer)
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
		MODULE_DATA& data = buffer.back();

		std::string& ModulePath = data.path;
		ModulePath = path;

		data.name = ModulePath.substr(ModulePath.find_last_of('\\') + 1);
		data.lpvRemoteBase = handles[i];
	}

	return true;
}

bool MapDLL(HANDLE process, MODULE_DATA& dll)
{
	const IMAGE_SECTION_HEADER* sh = dll.sections;

	// Mapping PE headers
	if (!WPM(process, dll.lpvRemoteBase, dll.ImageBase, sh[0].PointerToRawData))
	{
		PrintError("FAILED TO MAP PE HEADERS");
		return false;
	}

	// Mapping sections
	for (int i = 0; i < dll.NT_HEADERS->FileHeader.NumberOfSections; ++i)
	{
		void* section = dll.ImageBase + sh[i].PointerToRawData;
		void* SectionBuffer = reinterpret_cast<BYTE*>(dll.RemoteBase) + sh[i].VirtualAddress;

		if (!WPM(process, SectionBuffer, section, sh[i].Misc.VirtualSize))
		{
			PrintError("FAILED TO MAP SECTIONS");
			return false;
		}
	}

	return true;
}

bool RunDllMain(HANDLE process, const MODULE_DATA& dll)
{
	BYTE shellcode[] =
	{
		0x6A, 0x00,       // push 0     (lpvReserved)
		0x6A, 0x01,       // push 1     (fdwReason - DLL_PROCESS_ATTACH)
		0x68, 0, 0, 0, 0, // push 0     (hinstDLL)
		0xE8, 0, 0, 0, 0, // call 0     (DllMain)
		0x83, 0xC4, 0x04, // add esp, 4 (Must clean stack for CreateRemoteThread since DllMain is __stdcall)
		0xC3              // ret
	};

	void* pShellcode = __VirtualAllocEx(process, sizeof(shellcode), PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		PrintError("VirtualAllocEx[RunDllMain]");
		return false;
	}

	const DWORD EntryPoint = GetEP(dll) + dll.RemoteBase;
	*reinterpret_cast<DWORD*>(shellcode + 5) = dll.RemoteBase; // hinstDLL
	*reinterpret_cast<DWORD*>(shellcode + 10) = EntryPoint - (reinterpret_cast<DWORD>(pShellcode) + 14); // EP

	if (!WPM(process, pShellcode, shellcode, sizeof(shellcode)))
	{
		PrintError("WriteProcessMemory[RunDllMain]");
		return false;
	}

	std::cout << "EP: 0x" << std::hex << std::uppercase << (DWORD)pShellcode << '\n';
	system("pause");

	if (!__CreateRemoteThread(process, pShellcode, nullptr))
	{
		PrintError("CreateRemoteThread[RunDllMain]");
		return true;
	}
	
	return true;
}