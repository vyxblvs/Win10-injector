#include "pch.h"
#include "mMap.hpp"
#include "injector.hpp"
#include "LoadLib.hpp"
#include "process.hpp"

// Error handling is to be cleaned up once manual mapping is functional, especially ConvertRVA errors.

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
		PrintError("LoadLibraryA injection failed\n", IGNORE_ERR);
		CloseHandle(process);
		return 1;
	}
	else if (method == ManualMap)
	{
		const bool status = ManualMapDll(process, DllPath);

		for (auto& data : LoadedModules)
		{
			if (data.ImageBase) delete[] data.ImageBase;
		}
		LoadedModules.clear();

		for (auto& data : modules)
		{
			delete[] data.ImageBase;
		}
		modules.clear();

		if (!status)
		{
			PrintError("Manual map injection failed!\n", IGNORE_ERR);
			CloseHandle(process);
			return 1;
		}
	}

	std::cout << "DLL Successfully Injected!\n";
	CloseHandle(process);
	return 0;
}