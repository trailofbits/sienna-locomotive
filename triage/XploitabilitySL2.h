#include "Xploitability.h"


namespace sl2 {

class XploitabilitySL2 : Xploitability {
public:
    XploitabilitySL2::XploitabilitySL2(Minidump *dump,
                                     ProcessState *process_state);    


    virtual XploitabilityResult             process();

};


}