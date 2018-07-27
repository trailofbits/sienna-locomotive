#include <string>
#include <iostream>

#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "simple_symbol_supplier.h"
#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "Xploitability.h"
#include "XploitabilityTracer.h"

#include <filesystem>


#include "vendor/json.hpp"
using json = nlohmann::json;
namespace fs = std::experimental::filesystem;

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


    StatusCode                  process();
    const string                triagePath();
    const string                crashReason() const;
    const uint64_t              crashAddress() const;
    const string                exploitability() const;
    XploitabilityRank           exploitabilityRank() const;
    json                        toJson() const;
    friend ostream&             operator<< (ostream& os, Triage& self);
    int                         signalType();
    static double               normalize(double x);
    vector<XploitabilityRank>   ranks() const;
    const string                ranksString() const;
    void                        persist(const string path) const;
    const string                path() const;

private:
    const string                    path_;
    ProcessState                    state_;
    MinidumpProcessor               proc_;
    SimpleSymbolSupplier            symbolSupplier_;
    BasicSourceLineResolver         resolver_;
    Minidump                        dump_;
    vector<XploitabilityResult>     results_;
    fs::path                        dirPath_;
    uint64_t                        instructionPtr_;
    uint64_t                        stackPtr_;
    unique_ptr<XploitabilityTracer> tracer_;


};

} // namespace
