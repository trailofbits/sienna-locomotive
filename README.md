# Sienna Locomotive 2

Sienna Locomotive is a fuzzing and crash triage system with usability features that are intended to attract a wider user base than conventional fuzzing tools. The goal is to bring all the power that software fuzzing has to offer into the hands of less-experienced users. Focusing on ease of use won't stop us from trying to make it smarter and faster than the competition.

## Getting Started

### The project
Skim the following documents to familiarize yourself with the project:
* Watch the [Demo video](https://drive.google.com/open?id=1njGgRrrfNanYSuaMy5nwLi1rw2bS1rMt)
* [Interim Technical Report](https://docs.google.com/document/d/1zTUHlu-y_ZLT08saJp0qguYXC69F6CskMPZVLs48IVc/edit)
* [SL2 Reinception Doc ](https://docs.google.com/document/d/1RwvknJk9PPgecLcsQI1SiXje9SdKB3OuOoSniIDvy68/edit)
* harness.py (if you're familiar with Python)
* Read through the [Projects](https://github.com/trailofbits/sienna-locomotive/projects/6) and [Issues](https://github.com/trailofbits/sienna-locomotive/issues) pages on GitHub

## High level architecture

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
  Sent bytes by fuzzing harness
  Figures out mutations for bytes
  Sends back mutations
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

If you're not familiar with cmake - the first invocation configures it, the second compiles the project. To recompile, just run the final command again.

You might need to use the Visual Studio Developer Command Prompt in order for cmake to be able to see the VS compiler.

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

### Configuring
Open up powershell in the project root and run harness.py for the first time.

`PS C:\proj\sl2\sienna-locomotive> python .\harness.py`

:warning: Python version 3 is required, although on some systems this could be `python.exe` or `python3.exe` .

It'll create a default configuration file in `%APPDATA\Trail of Bits\fuzzkit\`. You can leave everything in there and it will work, but you might want to update the file paths to be relative to C: so that you can invoke it from anywhere. If you want to create a new profile, just copy the default one and change the name. Then you can use the `-p` flag to harness.py to change which profile it pulls settings from.

Using -h on the harness will print out the list of command line options it supports. You can set a number of things permanently by adding lines to the configuration file. As a general rule though, the command line parameters will overwrite what's in the config file if you explicitly pass them in. This isn't the case for everything, so if a command isn't working the way you expect, run fuzzer_config.py with the same arguments to see exactly what settings are getting passed to the harness.

### Running

#### Via the GUI
`python3 gui.py` will run the Qt frontend for the fuzzer. While it provides a convenient way of invoking the components, it doesn't provide as many configuration options. Fortunately, it accepts most of the same command line arguments as the harness, so you can simply pass these in when you invoke the GUI.
For example: `python3 gui.py -c -f 15 -i 360` will run the gui such that it invokes the fuzzer in continuous mode with a timeout of 15 seconds for each fuzzing run and a timeout of 360 seconds for each triage run. However, it does NOT respect the -e flag, nor any of the flags that would be overwritten from the config file if invoked on the harness.

#### Via the harness
`python3 harness.py` will run the test application in fuzzing mode. By default, the test application will crash after a few fuzzing attempts, so if it doesn't do so when you need it to, you can pass `-a 0` to the harness (as the last argument) and it will crash every time. Play around with the command flags to see what else you can do.

#### To run individual components manually
From the root of the project -
```
# General Pattern:
.\dynamorio\bin64\drrun.exe -c build\client_name\Debug\client.dll [client_args] -- C:\path\to\target_application [target_args]

# triage
.\dynamorio\bin64\drrun.exe -c build\triage_dynamorio\Debug\tracer.dll -- corpus\win_asm\crashes.exe 7

# wizard
.\dynamorio\bin64\drrun.exe -c build\wizard\Debug\wizard.dll -- build\corpus\test_application\Debug\test_application.exe 0

# server
build\server\Debug\server.exe

# fuzzer
.\dynamorio\bin64\drrun.exe -c build\fuzz_dynamorio\Debug\fuzzer.dll -- build\corpus\test_application\Debug\test_application.exe 0 -f

# triage crash
.\dynamorio\bin64\drrun.exe -c sienna-locomotive\build\triage_dynamorio\Debug\tracer.dll -r [RUN_ID] -- build\corpus\test_application\Debug\test_application.exe 0 -f

# targeting
.\dynamorio\bin64\drrun.exe -c build\fuzz_dynamorio\Debug\fuzzer.dll -t 0,ReadFile -- build\corpus\test_application\Debug\test_application.exe 0 -f

.\dynamorio\bin64\drrun.exe -c build\triage_dynamorio\Debug\tracer.dll -r [RUN_ID] -t 0,ReadFile -- build\corpus\test_application\Debug\test_application.exe 0 -f
```

#### Regression Test
```
python.exe .\regress.py
test_main (__main__.Test1) ... ok

----------------------------------------------------------------------
Ran 1 test in 0.906s

OK
```

## File Formats

### FKT Format

This format is for recording mutation events for later replay.

`char magic[4] == 'FKT\x00'`

`uint type`, `1 == file`

Variable based on type.

`uint file_size`

`wchar_t path[file_size]`

`size_t position`

`size_t size`

`uchar data[size]`


There's a 010 template for this in `misc`

### Outdated components
You can safely ignore most of the stuff in `corpus/asm` and `electriage`
