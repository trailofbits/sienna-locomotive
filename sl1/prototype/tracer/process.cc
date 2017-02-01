#include "process.h"

#include <iostream>
#include <algorithm>
#include <fstream>
#include <string>


int MemoryMap::load()
{
    std::ostringstream path;
    path << "/proc/" << _pid << "/maps";
    std::ifstream maps(path.str());
    int i;

    if (_pid == 0) {
        return 0;
    }

    Entry e;
    for (i = 0; maps >> e; i++) 
        _maps.push_back(e);
    
    return i;
}

std::istream &operator>>(std::istream &s, MemoryMap::Entry &entry)
{
  uintptr_t start, end, offset;
  int dev_start, dev_end, inode;
  char _c, permissions_c[4];
  std::string line, permissions;
  int read;

  if (!std::getline(s, line))
    return s;
 

  std::sscanf(line.c_str(),
    "%lx-%lx %4s %lx %d:%d %d%n", &start, &end, permissions_c, &offset, &dev_start, &dev_end, &inode, &read);
  permissions = std::string(permissions_c);
  std::string path = line.substr(read);
  path.erase(path.begin(), std::find_if_not(path.begin(), path.end(), ::isspace));

  entry.address = start;
  entry.size = end - start;
  entry.permissions = 0;
  if (permissions.find('r') != std::string::npos) 
    entry.permissions |= MemoryMap::Entry::PERM_READ;
  if (permissions.find('w') != std::string::npos)
    entry.permissions |= MemoryMap::Entry::PERM_WRITE;
  if (permissions.find('x') != std::string::npos)
    entry.permissions |= MemoryMap::Entry::PERM_EXEC;

  entry.dev = std::make_pair(dev_start, dev_end);
  entry.inode = inode;
  entry.path = path;

  return s;
}

bool 
MemoryMap::readEntry(std::ifstream &from) {
    Entry e;
    std::string permissions;
    uintptr_t start, end;
    char c;

    std::string line;
    from >> std::hex >> start >> c >> end;

    from >> permissions;
    return true;

  }