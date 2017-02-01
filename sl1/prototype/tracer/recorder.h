
#include <cstdint>
#include <array>
#include <vector>
#include <sys/user.h>
#include <fstream>

#include "tracer.h"
#include "Trace.pb.h"

using std::vector;
using std::string;

//template <typename RegMap>
class Recorder {

public:

  struct State {
    struct user_regs_struct registerState;
    vector<uint8_t> instruction;
    int status;
  };

public:

  explicit Recorder(const std::string &trace_path, const vector<string> argv)
  : _outs {trace_path}
  {
    assert (argv.size() > 0);

    _header.set_path(argv[0]);
    for (const auto &arg : argv)
      _header.add_cmdline(arg);
    _header.set_machine_width(sizeof(void*) * 8);

    _writeHeader();
  }

  /**
   * @brief Log an instance of State to disk.
   *
   * @param The program state to be logged
   */
  void recordState(const State &state);

  /**
   *
   */
  void setBinaryPath(const std::string binary_path);

private:
  void _writeState(const std::string &data);
  void _writeHeader();

  TraceHeader _header;
  std::ofstream  _outs;
  State _previous_state;
  uint64_t _written = 0;
};
