#ifndef EXPLOITABILITY_SL2_H
#define EXPLOITABILITY_SL2_H

#include "Xploitability.h"

namespace sl2 {
class XploitabilitySL2 : public Xploitability {
public:
    
    XploitabilitySL2( Minidump* dmp, ProcessState* state );
    virtual XploitabilityResult              process();
    
    
    friend XploitabilityResult& operator<<( XploitabilityResult& result, const ExploitabilityRating& rating );


private:
    ExploitabilityRating            processExploitabilityRating();
    ExploitabilityRating            rating_;

};

} // namespace

#endif