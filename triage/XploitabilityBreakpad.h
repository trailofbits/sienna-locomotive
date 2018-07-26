#ifndef XploitabilityBreakpad_H
#define XploitabilityBreakpad_H

#include "Xploitability.h"

namespace sl2 {
class XploitabilityBreakpad : public Xploitability {
public:
    
    XploitabilityBreakpad( Minidump* dmp, ProcessState* state );
    virtual XploitabilityResult              process();
    
    
    friend XploitabilityResult& operator<<( XploitabilityResult& result, const ExploitabilityRating& rating );


private:
    ExploitabilityRating            processExploitabilityRating();
    ExploitabilityRating            rating_;

};

} // namespace

#endif