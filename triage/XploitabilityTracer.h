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


    virtual XploitabilityResult             process();
    json                                    toJson() const;



protected:
    void                                    loadJson();
    json                                    json_;

    const string                            crashJsonPath_;

};

} // namespace


#endif