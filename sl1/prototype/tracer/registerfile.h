#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <type_traits>
#include <boost/bimap.hpp>
#pragma once

/**
 * @brief Rerpresents an instance of all the registers
 */
class RegisterFile {

public:

  /** @brief The type of the register itself. */
  using type = unsigned long long;

  /* @brief Map type for storing differences in RegisterFiles */
  using register_delta = std::map<unsigned, type>;


  RegisterFile():_registers_struct{0} {
  }

  /**
   * @brief Create a RegisterFile from a ptrace-returned register window
   */
  RegisterFile(const struct user_regs_struct *window)
  {
    _registers_struct = *window;

    if (!_map_initialized) {
      _initializeMap();
      _map_initialized = true;
    }
  }

  /**
   * @brief Produce a difference between two register states
   *
   * @param rhs The register file with which to compare
   */
  register_delta getDelta(const RegisterFile &rhs) const {
    register_delta delta;

    // std::remove_copy_if(_registers.begin(), _registers.end(), 
    //   delta.begin(), [](type x)
    // {
    //   return true;
    // });
    ///// std::accumulate(_registers.begin(), _registers.end(), )

    for (int i = 0; i < sizeof(_registers)/sizeof(_registers[0]); ++i) {
     if (_registers[i] != rhs._registers[i]) {
       delta.emplace(i, rhs._registers[i]);
     }
    }
    return delta;
  }

  /**
   * @brief Return the value of a register by name
   *
   * @param name The name of the register (i.e. "rip")
   */
  type getValue(std::string &name) {
    return _registers[getIndex(name)];
  }
  
private:

  size_t getIndex(const std::string &name) {
    return kRegisterNameMap.left.find(name)->second;
  }


  static boost::bimap<std::string, unsigned int> kRegisterNameMap;
  
  static bool _map_initialized;

  static void _initializeMap() {
    using entry = boost::bimap<std::string, unsigned int>::value_type;
    unsigned int idx = 0;
    const char *registers[] = { "r15", "r14", "r13", "r12", "rbp", "rbx",
        "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", 
        "orig_rax", "rip", "cs", "eflags", "rsp""ss", "fs_base""gs_base"
        "ds", "es", "fs", "gs"
      };
    for (auto v : registers) {
      kRegisterNameMap.insert( entry(v, idx++));
    }
  }

  constexpr static size_t kRegisterSize = sizeof(struct user_regs_struct)/sizeof(type);

  union {
    std::array<type, kRegisterSize> _registers;
    //type _registers[kRegisterSize];
    struct user_regs_struct _registers_struct;
  };
};
