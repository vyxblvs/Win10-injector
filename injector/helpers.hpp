#pragma once

bool GetModule(HANDLE process, const std::string& name, DLL_DATA* buffer);

DLL_DATA* GetDllData(const char* name, int* pos = nullptr, bool* ReturnedVec = nullptr);

std::string UnicodeToMultibyte(UNICODE_STRING& wstr);