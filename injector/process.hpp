#pragma once

bool GetLoadedModules(HANDLE process, std::vector<module_data>& buffer);