#include <string>
#include "triage.h"



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
            if( triage.ranks()[0]==triage.ranks()[1] ) {
                parity++;
            }
            cout << triage << endl;
        } catch (...) {
            cout << "error" << endl;
        }
    }

    cout << "Parity: " << parity << " of " << i <<  endl;

}