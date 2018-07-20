#include <string>

#include "google_breakpad/processor/process_state.h"

using namespace std;
using namespace google_breakpad;

namespace sl2 {

enum StatusCode {
    GOOD,
    ERROR
};


class Triage {

public:
    Triage( const string& path );

    StatusCode      process();
    float           exploitability();

private:
    const string    path_;
    ProcessState    state_;

};

} // namespace
