// XXX_INCLUDE_TOB_COPYRIGHT_HERE

// This is the main triage class that works on a single minidump file (versus triager.cc which handles command line, multiple files, etc.
// It runs the 3 processors (!exploitable, breakpad, and tracer) on the minidump.  The tracer processor is a little special since it can
// have our taint information.  From the processors the highest score is used for the exploitability.  The exploitability and important
// details from the crash and minidump analysis are put in a triage.json file.

#ifndef Triage_H
#define Triage_H

#include "Xploitability.h"
#include "XploitabilityTracer.h"
#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "simple_symbol_supplier.h"
#include <filesystem>
#include <iostream>
#include <string>

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
    XploitabilityRank           exploitabilityRank()        const;
    const string                crashReason()               const;
    const string                exploitability()            const;
    const string                minidumpPath()              const;
    const string                ranksString()               const;
    const string                stackHash()                 const;
    const string                triageTag()                 const;
    const uint64_t              crashAddress()              const;
    const uint64_t              instructionPointer()        const;
    const uint64_t              stackPointer()              const;
    const vector<uint64_t>      callStack()                 const;
    friend ostream&             operator<< (ostream& os, Triage& self);
    int                         signalType();
    json                        toJson()                    const;
    static double               normalize(double x);
    vector<XploitabilityRank>   ranks()                     const;
    void                        persist(const string path)  const;

private:

    BasicSourceLineResolver         resolver_;
    Minidump                        dump_;
    MinidumpProcessor               proc_;
    ProcessState                    state_;
    SimpleSymbolSupplier            symbolSupplier_;
    const string                    minidumpPath_;
    fs::path                        dirPath_;
    unique_ptr<XploitabilityTracer> tracer_;
    vector<XploitabilityResult>     results_;

};

} // namespace

#endif