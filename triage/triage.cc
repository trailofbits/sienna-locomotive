////////////////////////////////////////////////////////////////////////////
// Trail of Bits
// July 2018
////////////////////////////////////////////////////////////////////////////
#include <string>
#include "triage.h"


#include <iostream>
#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "google_breakpad/processor/minidump.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "simple_symbol_supplier.h"
// #include "cfi_frame_info.h"

using namespace std;
using namespace google_breakpad;

using google_breakpad::MinidumpProcessor;
using google_breakpad::ProcessState;
using google_breakpad::SimpleSymbolSupplier;


namespace sl2 {

////////////////////////////////////////////////////////////////////////////
// Triage()
//
// Constructor for Triage class which loads a minidump file at path
////////////////////////////////////////////////////////////////////////////
Triage::Triage( const string& path ) 
    : path_(path)
{
}

////////////////////////////////////////////////////////////////////////////
// process()
//      Does actual processing a minidump file
StatusCode Triage::process() {
    SimpleSymbolSupplier    symbolSupplier(path_);

    BasicSourceLineResolver resolver;
    MinidumpProcessor proc(&symbolSupplier, &resolver, true);

    ProcessResult   sc;

    sc = proc.Process(path_, &state_);
    if( PROCESS_OK!=sc ) {
        return StatusCode::ERROR;
    }

    proc.set_enable_objdump(false);
    
    cout << "Exploitability: " << exploitability() << endl;
    
    return StatusCode::GOOD;
}


////////////////////////////////////////////////////////////////////////////
// exploitability()
//      returns value from 0.0 to 1.0 for exploitabilty
float Triage::exploitability() {

    switch(state_.exploitability()) {
        case EXPLOITABILITY_HIGH:
            return 1.0;
            break;
        case EXPLOITABILITY_MEDIUM:
            return 0.5;
            break;
        case EXPLOITABILITY_INTERESTING:
            return 0.3;
            break;
        case EXPLOITABILITY_LOW: 
            return 0.01;
            break;
        default:
            return 0.0;
            break;
    }
}

} // namespace