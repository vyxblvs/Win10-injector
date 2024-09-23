#pragma once

bool GetModule(HANDLE process, const std::string name, module_data* buffer);

module_data* FindModule(const char* name, int* pos = nullptr, int* ReturnedVec = nullptr);

std::string UnicodeToMultibyte(UNICODE_STRING& wstr);