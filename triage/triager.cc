#include <string>
#include "triage.h"
#include <iostream>
#include <fstream>

#include "statz.h"
using namespace std;


int main(int argc, char* argv[] ) {

    uint32_t parity = 0;
    int i=1;

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

