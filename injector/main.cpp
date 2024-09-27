#include "pch.h"
#include "mMap.hpp"
#include "injector.hpp"
#include "LoadLib.hpp"
#include "process.hpp"

// Error handling is to be cleaned up once manual mapping is functional, especially ConvertRVA errors.

int PrintError(const char* msg, ErrorFlags ErrorMode, const char* rvaDesc)
{
	switch (ErrorMode)
	{
	case RVA_CONVERT_ERR: std::cerr << "ERROR: FAILED TO CONVERT RVA (" << rvaDesc << ")\n"; break;
	case GET_LAST_ERR:    std::cerr << "ERROR: " << msg << " (" << GetLastError() << ")\n";  break;
	default:              std::cerr << "ERROR: " << msg << '\n';
	}

	return 0;
}

int PrintErrorRVA(const char* rvaDesc) 
{ 
	return PrintError(nullptr, RVA_CONVERT_ERR, rvaDesc);
}

// THIS INJECTOR IS MADE FOR x86 PROCESSES/DLLS

// Argument format: injector.exe [process_name.exe] [dll_path.dll] [injection method]
// Injection method defaults to LoadLibraryW if one is not specified
// Arguments are NOT case sensitive

int wmain(int argc, wchar_t* argv[])
{
	const wchar_t* ProcessNameW;
	const wchar_t* DllPathW;
	bool method = LoadLib;

	// Checking arguments
	if (argc < 3)
	{
		PrintError("Invalid Arguments", IGNORE_ERR_CODE);
		return 1;
	}
	else
	{
		ProcessNameW = argv[1];
		DllPathW = argv[2];

		if (argc > 3) 
		{
			if (_wcsicmp(argv[3], L"ManualMap") == 0) 
			{
				method = ManualMap;
			}
			else if (_wcsicmp(argv[3], L"LoadLibraryW") != 0)
			{
				// Does not default to LoadLibraryW in this case to avoid unwanted injection
				PrintError("Invalid injection method", IGNORE_ERR_CODE);
				return 1;
			}
		}
	}
	
	const HANDLE process = GetProcessHandle(ProcessNameW);
	if (!process) return 1;

	if (method == LoadLib && !LoadLibInject(process, DllPathW))
	{
		PrintError("LoadLibraryW injection failed\n", IGNORE_ERR_CODE);
		CloseHandle(process);
		return 1;
	}
	else if (method == ManualMap)
	{
		char DllPathA[MAX_PATH + 1];
		wcstombs(DllPathA, DllPathW, MAX_PATH);

		const bool status = ManualMapDll(process, DllPathA);

		ApiSets.clear();

		for (auto& dll : LoadedModules)
		{
			if (dll.ImageBase) delete[] dll.ImageBase;
		}
		LoadedModules.clear();

		for (auto& dll : modules)
		{
			delete[] dll.ImageBase;
		}
		modules.clear();

		if (!status)
		{
			PrintError("Manual map injection failed!\n", IGNORE_ERR_CODE);
			CloseHandle(process);
			return 1;
		}
	}

	std::cout << "DLL Successfully Injected!\n";
	CloseHandle(process);
	return 0;
}