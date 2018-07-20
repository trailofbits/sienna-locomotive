#ifndef Xploitability_H
#define Xploitability_H

#include "google_breakpad/common/breakpad_types.h"
#include "google_breakpad/processor/exploitability.h"
#include "google_breakpad/processor/process_state.h"

using namespace google_breakpad;


namespace sl2 {
class Xploitability : public Exploitability {
public:
    
    Xploitability( Minidump* dmp, ProcessState* state ): Exploitability(dmp, state){  }
    virtual double                  exploitabilityScore() = 0;
    virtual ExploitabilityRating    CheckPlatformExploitability() = 0;

protected:
    uint32_t  exploitabilityWeight_;
};

} // namespace

#endif