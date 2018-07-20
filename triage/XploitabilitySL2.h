#ifndef EXPLOITABILITY_SL2_H
#define EXPLOITABILITY_SL2_H

#include "Xploitability.h"

namespace sl2 {
class XploitabilitySL2 : public Xploitability {
public:
    
    XploitabilitySL2( Minidump* dmp, ProcessState* state );

    virtual double                  exploitabilityScore();    
    virtual ExploitabilityRating    CheckPlatformExploitability();

};

} // namespace

#endif