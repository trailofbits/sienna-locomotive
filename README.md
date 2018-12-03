# Sienna Locomotive 2

[![Build Status](https://travis-ci.com/trailofbits/sienna-locomotive.svg?token=DQQpqJG5gna6rypMg4Lk&branch=master)](https://travis-ci.com/trailofbits/sienna-locomotive)

Sienna Locomotive is a fuzzing and crash triage system with usability features that are intended to attract a wider user base than conventional fuzzing tools. The goal is to bring all the power that software fuzzing has to offer into the hands of less-experienced users. Focusing on ease of use won't stop us from trying to make it smarter and faster than the competition.

## Getting Started

### High level architecture

```
Wizard
  Run the target program once
  Find all the functions the fuzzer can target
  Return a list the user can select from

Fuzzing harness
  Run the target program
  Hook attack surface functions
  Execute program with mutated inputs
  Catch crashes for tracer

Triage
  Traces and performs taint tracking on a crashing execution
  Combines data about crash, inputs, and taint
  Output score and JSON info about crash

Mutation Server
  Sent bytes and coverage statistics by fuzzing harness
  Sends back mutation advice
  Responsible for logging information about corrupted inputs

Python harness
  Handles user input and configuration
  Runs all the other components
```

### Building
First, clone the repository:
`git clone https://github.com/trailofbits/sienna-locomotive.git` (or download a zip)

#### Dependencies
Next, install the following dependencies
* [CMake](https://cmake.org/download/)
* Visual Studio 2017 (Install components for Windows Console dev)
* DynamoRIO (Automatically installed with make.ps1)
* Python (3.6+)

#### Build Commands

Then, from the root of the Sienna Locomotive repository:
In powershell, run make.ps1:

`PS C:\proj\sl2\sienna-locomotive> .\make.ps1`

This should download and install DynamoRIO in the sienna-locomotive directive if it does not already exist.  It will then compile the project.

You might need to use the Visual Studio Developer Command Prompt in order for cmake to be able to see the VS compiler.

Next, run the following to configure the python environment:

`python setup.py develop`

Use `.\make.ps1 clean` for a clean build .

Usage `make.ps1 help` for more info.

```
PS C:\proj\sl2\sienna-locomotive> .\make.ps1 help
Usage: make1.ps [clean|dep|reconfig|help]

make1.ps without any options will build

clean
    Cleans build directory and configuration (reconfigs)

dep
    Rebuild dependencies

reconfig
    Deletes fuzzkit directory with run configuration

help
    This info
```

#### Documents
If you want to build the doxygen documents.
  1. Install doxygen from http://ftp.stack.nl/pub/users/dimitri/doxygen-1.8.14-setup.exe
  1. `./make doc`
  1. Look in `doc/html/index.html`

### Configuring
Open up powershell in the project root and run the gui for the first time.

`PS C:\proj\sl2\sienna-locomotive> sl2`

It'll create a default configuration file in `%APPDATA\Trail of Bits\fuzzkit\`. You can leave everything in there and it will work, but you might want to update the file paths to be relative to C: so that you can invoke it from anywhere. If you want to create a new profile, just copy the default one and change the name. Then you can use the `-p` flag to `sl2` to change which profile it pulls settings from.

Using -h on the harness will print out the list of command line options it supports. You can set a number of things permanently by adding lines to the configuration file. As a general rule though, the command line parameters will overwrite what's in the config file if you explicitly pass them in. This isn't the case for everything, so if a command isn't working the way you expect, run fuzzer_config.py with the same arguments to see exactly what settings are getting passed to the harness.

### Running

#### Via the GUI
`sl2` will run the Qt frontend for the fuzzer. While it provides a convenient way of invoking the components, it doesn't provide as many configuration options. Fortunately, it accepts most of the same command line arguments as the harness, so you can simply pass these in when you invoke the GUI.
For example: `sl2 -f 15 -i 360` will run the gui such that it invokes the fuzzer with a timeout of 15 seconds for each fuzzing run and a timeout of 360 seconds for each triage run. However, it does NOT respect the -e flag, nor any of the flags that would be overwritten from the config file if invoked on the harness.

#### Via the harness
`sl2-cli` will run the test application in fuzzing mode. By default, the test application will crash after a few fuzzing attempts, so if it doesn't do so when you need it to, you can pass `-a 0` to the harness (as the last argument) and it will crash every time. Play around with the command flags to see what else you can do.

#### To run individual components manually
From the root of the project -
```
# General Pattern:
.\dynamorio\bin64\drrun.exe -c build\client_name\Debug\client.dll [client_args] -- C:\path\to\target_application [target_args]

# triage
.\dynamorio\bin64\drrun.exe -c build\tracer_dynamorio\Debug\tracer.dll -- corpus\win_asm\crashes.exe 7

# wizard
.\dynamorio\bin64\drrun.exe -c build\wizard\Debug\wizard.dll -- build\corpus\test_application\Debug\test_application.exe 0

# server
build\server\Debug\server.exe

# fuzzer
.\dynamorio\bin64\drrun.exe -c build\fuzz_dynamorio\Debug\fuzzer.dll -- build\corpus\test_application\Debug\test_application.exe 0 -f

# triage crash
.\dynamorio\bin64\drrun.exe -c sienna-locomotive\build\tracer_dynamorio\Debug\tracer.dll -r [RUN_ID] -- build\corpus\test_application\Debug\test_application.exe 0 -f

# targeting
.\dynamorio\bin64\drrun.exe -c build\fuzz_dynamorio\Debug\fuzzer.dll -t 0,ReadFile -- build\corpus\test_application\Debug\test_application.exe 0 -f

.\dynamorio\bin64\drrun.exe -c build\tracer_dynamorio\Debug\tracer.dll -r [RUN_ID] -t 0,ReadFile -- build\corpus\test_application\Debug\test_application.exe 0 -f
```

#### Regression Test
```cmd
> sl2-test.exe

test_0 (sl2.test.regress.TestWizard) ... ok
test_2 (sl2.test.regress.TestWizard) ... ok
test_TheWiz (sl2.test.regress.TestWizard) ... ok
test_captureStdout (sl2.test.regress.TestWizard) ... ok
test_quickCrash (sl2.test.regress.TestWizard) ... ok
test_registry (sl2.test.regress.TestWizard) ... ok
test_triage (sl2.test.regress.TestWizard) ... ok

----------------------------------------------------------------------
Ran 7 tests in 49.421s

OK
```

## Triage

The triage system is a separate executable, `triager.exe` that is run by the harness.  It takes care of ranking exploitability, uniqueness, and binning of crashes.

### Winchecksec

Read the [winchecksec README](https://github.com/trailofbits/winchecksec).

### Exploitability

The Exploitability ranking is a score for the potential ability to exploit a crash based on 3 engines.  The ranks, ranging from High (4) to None (0), in order of likelyhood are:

  * **High** (4): The mostly likely case of a crash being exploitable.
  * **Medium** (3): Between High and Low.
  * **Low** (2): At or above the cutoff for low exploitability.
  * **Unknown** (1): Unknown cases are below the cutoff for low, but still have the potential to be of interest.
  * **None** (0): Very unlikely the crash is exploitable.

#### Engines

  * **Google's Breakpad**: This engine uses Google's Breakpad library, which parses minidump files and return an exploitability between High and None as well.
  * **Microsoft's `!exploitable`**: A reimplementation and approxmiation of the `!exploitable` command for `windbg`, built on top of breakpad.
  * **SL2 Tracer**: Uses the score from our own SL2 tracer, which takes taint information into consideration.

### triage.json

After the tracer has been run, `triager.exe` is run on the minidump file. It also loads any information generated by the tracer, and outputs the following json:

```c
{
    // This is the called functions before the crash
    "callStack": [
        140699242310037,
        140718144357416,
        140718144581792,
        140718144447545
    ],

    // The offending memory address
    "crashAddress": 140699242310037,

    // The reason of exception type
    "crashReason": "EXCEPTION_BREAKPOINT",

    // Exploitability from High to None
    "exploitability": "Unknown",

    // The instruction pointer at the time of the crash
    "instructionPointer": 14757395258967641292,

    // Path to the minidump analyzed
    "minidumpPath": "C:\\Users\\IEUser\\AppData\\Roaming\\Trail of Bits\\fuzzkit\\runs\\78f20c60-eb12-410a-8378-342c3afec986\\initial.dmp",

    // Rank, or numeric version of exploitability from 0-4
    "rank": 1,

    // The ranks generated by each of the 3 engines
    "ranks": [
        0,
        0,
        1
    ],

    // A unique identifier for the crash. The algorithm uses 12 bits from the called functions,
    // and is unaffected by ASLR, function call order, or function call count
    "crashash": "f96808cfc4798256",

    // Stack pointer at time of crash
    "stackPointer": 14757395258967641292,

    // Unique tag for the crash for binning purposes
    "tag": "Unknown/EXCEPTION_BREAKPOINT/f96808cfc4798256",

    // Complete output from the tracer run
    "tracer": {
        "exception": "EXCEPTION_BREAKPOINT",
        "instruction": "int3",
        "last_calls": [
            140699242861232,
            140699242861064,
            140699242861064,
            140699242861056,
            140699242861184
        ],
        "last_insns": [
            140699242309722,
            140699242309725,
            140699242309727,
            140699242309730,
            140699242310037
        ],
        "location": 140699242310037,
        "reason": "breakpoint",
        "regs": [
            {
                "reg": "rax",
                "tainted": false,
                "value": 1080890113
            },
            //...............................................
        ],
        "score": 25,
        "tainted_addrs": [
            {
                "size": 8,
                "start": 2645403054665
            }
        ]
    }
}
```

### Outdated components
You can safely ignore most of the stuff in `corpus/asm`.

# Changes

## 20180808
Changed passing of arguments to clients and target applications from using comma separated to just normally how it would appear on the command line. The `shlex.split()` function will split them up appropriately


# Developer Information

If you change anything that would break backwards compatibility, increment  `harness.config.VERSION`.  This includes any database changes, formats, directory structures, filenames etc..
