#include <string>
#include <iostream>

#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "simple_symbol_supplier.h"
#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "exploitability_sl2.h"

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
    ~Triage( );


    StatusCode          process();
    const string        triagePath();
    const string        crashReason();
    const string        exploitability();
    double              exploitabilityScore();
    friend ostream&     operator<< (ostream& os, Triage& self);
    int                 signalType();
    static double       normalize(double x);

private:
    const string            path_;
    ProcessState            state_;
    MinidumpProcessor       proc_;
    SimpleSymbolSupplier    symbolSupplier_;
    BasicSourceLineResolver resolver_;
    Minidump                dump_;
    ExploitabilitySL2*      xploitabilityBreakpad_;
    vector<double>          scores_;


};

} // namespace
