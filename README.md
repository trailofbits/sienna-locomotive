# Sienna Locomotive 2

The primary goal is ease of use. That won't stop us from trying to make it faster and smarter than the competition too.

## Getting Started

### Building 

```
mkdir build
cd build
cmake -G"Visual Studio 15 Win64" -DDynamoRIO_DIR=C:\path\to\DynamoRIO\cmake ..
cmake --build .
```

### Running

From the root of the project - 

```
# triage
C:\path\to\DynamoRIO\bin64\drrun.exe -c build\triage_dynamorio\Debug\tracer.dll -- corpus\win_asm\crashes.exe 7

# wizard 
C:\path\to\DynamoRIO\bin64\drrun.exe -c build\wizard\Debug\wizard.dll -- build\corpus\test_application\Debug\test_application.exe 0

# server
build\server\Debug\server.exe

# fuzzer
C:\path\to\DynamoRIO\bin64\drrun.exe -c build\fuzz_dynamorio\Debug\fuzzer.dll -- build\corpus\test_application\Debug\test_application.exe 0 -f

# triage crash
C:\path\to\DynamoRIO\bin64\drrun.exe -c sienna-locomotive\build\triage_dynamorio\Debug\tracer.dll -r [RUN_ID] -- build\corpus\test_application\Debug\test_application.exe 0 -f

# targeting 
C:\path\to\DynamoRIO\bin64\drrun.exe -c build\fuzz_dynamorio\Debug\fuzzer.dll -t 0,ReadFile -- build\corpus\test_application\Debug\test_application.exe 0 -f

C:\path\to\DynamoRIO\bin64\drrun.exe -c build\triage_dynamorio\Debug\tracer.dll -r [RUN_ID] -t 0,ReadFile -- build\corpus\test_application\Debug\test_application.exe 0 -f
```

## File Formats

### Trace Format

This is an execution and event trace file.

Repeating elements, one of -

`byte size`, `byte insn_bytes[size]`

`byte 0x80`, `uint64 basic_block_address`

`byte 0x81`, `uint64 taint_address`, `uint64 taint_size`,

`byte 0x82`, `uint32 exception_code`, `uint64 exception_address`,

### FKT Format

This format is for recording mutation events for later replay.

`char magic[4] == 'FKT\x00'`

`uint type`, `1 == file`

Variable based on type.

`uint file_size`

`wchar_t path[file_size]`

`uint64 position`

`uint size`

`uchar data[size]`


## High level architecture

```
Fuzzer
  Run the target program
  Hook attack surface functions
  Execute program
  Catch crashes for tracer

Mutation Server
  Sent bytes by injectable
  Figures out clever mutations for bytes in down time
  Sends back mutations
  Responsible for logging information about corrupted inputs

Triage
  Traces and performs taint tracking on a crashing execution
  Combines data about crash, inputs, and taint 
  Output score and JSON info about crash
```

### ASM Crash Corpus

* Build `corpus/win_asm`, you'll likely need to change the paths in there
* (Come up with a good solution for this, maybe a config file and Python build script.)
* Run `fuzzkit.exe -t crashes.exe [arg]` for whatever crash you want to check (try 7 write_taint)
* (The above traces without fuzzing for standalone triage)
* Run `triage.exe -r [run_id]` for the run id that was created

## Research questions

```
Fuzzer
  Code coverage
    Good way to acheive this?
  Resetting executions 
    
Mutation Server
  Ideally pluggable with smart stuff (mcore, ai)
  What is the fastest method of interprocess communication (using named pipes right now)
  Smart mutations, file format aware, or code aware
  Needs some state for runs (has input order and file position information)

Tracer
  Fast tracing methods
    IntelPT (special hardware)
    Time travel debugging (no api)
    QEMU (requires custom modifications)
    Binary translation
  Identify branches, cache basic blocks for speed
  Proving ground for instrumentation in fuzzkit (too slow for this in its current state)
  Be able to run in standalone mode (done!)

Triage
  Really just a matter of implementing this
  Able to run in standalone mode
```

## Short Term Design thoughts

```
Code coverage / tracing   # problem 1
  Debugger
  DynamoRIO (can we use as a library?)
  Pin (can we use as a library?)
  VMill
```

