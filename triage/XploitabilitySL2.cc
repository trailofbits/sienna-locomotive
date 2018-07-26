#include "XploitabilitySL2.h"

namespace sl2 {

XploitabilitySL2::XploitabilitySL2(Minidump *dump,
                                     ProcessState *process_state)
    : Xploitability(dump, process_state, "sl2") {       
    }


XploitabilityResult XploitabilitySL2::process() { return XploitabilityResult{}; }



}
