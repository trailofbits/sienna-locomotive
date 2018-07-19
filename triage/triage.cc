// #include <iostream>
// #include "google_breakpad/processor/basic_source_line_resolver.h"
// #include "google_breakpad/processor/minidump.h"
// #include "google_breakpad/processor/minidump_processor.h"
// #include "google_breakpad/processor/process_state.h"
// #include "processor/simple_symbol_supplier.h"

// using namespace std;
// using namespace google_breakpad;

// using google_breakpad::MinidumpProcessor;
// using google_breakpad::ProcessState;
// using google_breakpad::SimpleSymbolSupplier;

// int main(int argc, char* argv[] ) {
//     //Exploitability* x = Exploitability::ExploitabilityForPlatform(nullptr, nullptr, nullptr);
//     string path(argv[1]);

//     cout << " Loading " << path << endl;

//     // TODO: add real symbol support

// #define MDUMP_SIMPLE
// #ifdef MDUMP_SIMPLE
//     Minidump minidump( path, 16 );
//     minidump.GetBreakpadInfo();
//     minidump.Read();
//     minidump.Print();
// #else



//     SimpleSymbolSupplier    symbolSupplier(path);
//     BasicSourceLineResolver resolver;
//     MinidumpProcessor proc(&symbolSupplier, &resolver, true);

//     ProcessResult   sc;
//     ProcessState    state;

//     sc = proc.Process(path, &state);
//     proc.set_enable_objdump(true);
//     cout << "Exploitability: " << state.exploitability() << endl;
// #endif
   
// }


 int main(int argc, char* argv[] ) {
     return -1;
 }