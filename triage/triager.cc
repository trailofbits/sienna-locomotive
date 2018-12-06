// XXX_INCLUDE_TOB_COPYRIGHT_HERE

// main() for triager.exe .


#include "statz.h"
#include "triage.h"
#include <fstream>
#include <iostream>
#include <string>

using namespace std;


void usage(char* argv[]) {
    cout << "Syntax : " << argv[0] << " <minidump1> [minidump2 ... minidumpN]" << endl;
    cout << "Example: " << argv[0] << " mem.dmp crash2.dmp" << endl;
}

int main(int argc, char* argv[] ) {

    uint32_t parity = 0;
    int i=1;

    if(argc==1) {
        usage(argv);
        return -1;
    }


    for( i=1; i<argc; i++ ) {
        try {
            sl2::Triage triage = string(argv[i]);
            sl2::StatusCode sc = triage.process();

            if(sc!=sl2::GOOD) {
                continue;
            }

            cout << triage << endl;
        } catch (...) {
            cerr << "error on processing "<< argv[i] << endl;
        }
    }


    return 0;

}

