#include <string>
#include <memory>
#include <sstream>
#include <iostream>
#include <vector>
#include <algorithm>

#include <boost/filesystem.hpp>

#pragma once

class MemoryMap {
public:
  struct Entry {
    uintptr_t address;
    size_t size;
    uint8_t permissions;
    std::pair<uint8_t, uint8_t> dev;
    int inode;
    std::string path;

    enum Permissions {
      PERM_READ  = 1,
      PERM_WRITE = 2,
      PERM_EXEC  = 4,
    };
  };

  MemoryMap() : _pid(0)
  {
  }

  int load();

  void setPid(int pid) { _pid = pid; }

  int pid() const { return _pid; }

  bool findContainingEntry(uintptr_t address, Entry &e) {
    auto it = std::find_if(_maps.begin(), _maps.end(), [=](auto &e) {
      return address >= e.address && address < (e.address + e.size);
    });
    if (it == _maps.end()) {
      return false;
    }
    
    e = *it;
    return true;
  }

private:
  bool readEntry(std::ifstream &from);
  int _pid;
  std::vector<Entry> _maps;
};

std::istream &operator>>(std::istream &s, MemoryMap::Entry &entry);


class Process {

  std::shared_ptr<MemoryMap> _mmap;
  boost::filesystem::path _absolute_path;
  int _pid;

public:
  void setPid(int pid) {
    _pid = pid;

    _mmap.reset(new MemoryMap());
    _mmap->setPid(_pid);
    _mmap->load();
  }

  int pid() const { return _pid; }

  void setAbsolutePath(boost::filesystem::path absolute_path) {
    _absolute_path = absolute_path;
  }

  bool addressWithinImage(uintptr_t addr) {
    MemoryMap::Entry e;

    if (!_mmap.get())
      return false;

    if (!_mmap->findContainingEntry(addr, e)) {
      return false;
    }

    return e.path == _absolute_path.string();
  }

};
