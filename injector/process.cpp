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
		module_data& data = buffer.back();

		std::string& ModulePath = data.path;
		ModulePath = path;

		data.name = ModulePath.substr(ModulePath.find_last_of('\\') + 1);
		data.lpvRemoteBase = handles[i];
	}

	return true;
}

bool MapDLL(HANDLE process, module_data& dll)
{
	const IMAGE_SECTION_HEADER* sh = dll.sections;

	// Mapping PE headers
	if (!WriteProcessMemory(process, dll.lpvRemoteBase, dll.ImageBase, sh[0].PointerToRawData, nullptr))
	{
		PrintError("FAILED TO MAP PE HEADERS", GET_LAST_ERR);
		return false;
	}

	// Mapping sections
	for (int i = 0; i < dll.NT_HEADERS->FileHeader.NumberOfSections; ++i)
	{
		void* section = dll.ImageBase + sh[i].PointerToRawData;
		void* SectionBuffer = reinterpret_cast<BYTE*>(dll.RemoteBase) + sh[i].VirtualAddress;

		if (!WriteProcessMemory(process, SectionBuffer, section, sh[i].Misc.VirtualSize, nullptr))
		{
			PrintError("FAILED TO MAP SECTIONS", GET_LAST_ERR);
			return false;
		}

		dll.RemoteSections.emplace_back(SectionBuffer);
	}

	return true;
}