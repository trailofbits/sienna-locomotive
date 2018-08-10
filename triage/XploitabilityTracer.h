// XXX_INCLUDE_TOB_COPYRIGHT_HERE

// Xploitability implementation for using sl2 tracer.cpp.  This scores based on taint information

#ifndef XploitabilityTracer_H
#define XploitabilityTracer_H

#include "Xploitability.h"

#include "vendor/json.hpp"
using json = nlohmann::json;


namespace sl2 {

class XploitabilityTracer : public Xploitability {
public:
    XploitabilityTracer::XploitabilityTracer(
                Minidump* dump,
                ProcessState* process_state,
                const string crashJson );

    json                                    toJson() const;
    virtual XploitabilityResult             process();

protected:
    const string                            crashJsonPath_;
    json                                    json_;
    void                                    loadJson();

};

} // namespace


#endif