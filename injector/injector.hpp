#pragma once

// Enums

enum InjectionMethod
{
	ManualMap = 0,
	LoadLib   = 1,
};

enum ErrorFlags
{
	IGNORE_ERR_CODE = 0,
	GET_LAST_ERR    = 1,
	RVA_CONVERT_ERR = 2
};

// Forward declarations

int PrintError(const char* msg, ErrorFlags ErrorMode = GET_LAST_ERR, const char* rvaDesc = nullptr);

int PrintErrorRVA(const char* rvaDesc);