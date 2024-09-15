#include "pch.h"
#include "manual_map.hpp"
#include "file_parsing.hpp"

/*
*  CURRENT GOAL(s)
*  - Apply relocation
*/

bool ManualMapDll(const HANDLE process, const char* DllPath)
{
	module_data TargetDLL;
	LoadDLL(DllPath, &TargetDLL);

	return true;
} 