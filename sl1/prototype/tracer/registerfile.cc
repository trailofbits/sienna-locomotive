#include "registerfile.h"

boost::bimap<std::string, unsigned int> RegisterFile::kRegisterNameMap;

bool RegisterFile::_map_initialized = 0;


