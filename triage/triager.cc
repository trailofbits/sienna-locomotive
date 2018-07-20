#include <string>
#include "triage.h"

int main(int argc, char* argv[] ) {

    sl2::Triage triage = string(argv[1]);
    triage.process();
}