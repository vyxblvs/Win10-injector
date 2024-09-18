#pragma once

/*
* TODO
* -	TLS execution
* - Thread hijacking
* - Improved error handling
* - Improved code readability
*/

// Macros

#define ManualMap    0

#define _LoadLibrary 1


#define IGNORE_ERR   0

#define GET_LAST_ERR 1

#define RVA_FAIL     2


// Forward declarations

void PrintError(const char* msg, int ErrorMode = GET_LAST_ERR, const char* rvaDesc = nullptr);

void PrintErrorRVA(const char* rvaDesc);