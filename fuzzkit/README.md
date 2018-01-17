# Fuzzing and Crash Triage

The primary goal is ease of use. That won't stop us from trying to make it faster and smarter than the competition too.

## High level architecture

```
Fuzzkit
  Launch the target program
  Load injectable and all dependencies into target program's memory
  Execute program
  Catch crashes for tracer

Injectable
  Contains hook functions for target program
  Communicates with mutation server to generate inputs

Mutation Server
  Sent bytes by injectable
  Figures out clever mutations for bytes in down time
  Sends back mutations
  Responsible for logging information about corrupted inputs

Tracer
  Ran to gather trace of crashing exeuction
  Able to recreate exact run of target application
  Outputs instruction length and bytes (for triton)
  Outputs taint sources 
  Outputs crash location (sink)
  Trace consumable by triage 

Triage
  Uses trace to perform taint tracking (Triton)
  Combines data about crash, inputs, and taint 
  Output score
```

## Getting Started

### Building 

* Download and install `boost`
* Copy `boost` headers to `sienna-locomotive/fuzzkit/triage/include`
* Download and install `z3`
* Copy `z3` headers to `sienna-locomotive/fuzzkit/triage/include`
* Open `fuzzkit.sln`
* Set build to `x64` and `Release`
* Build (optional: update `README` with solutions to build problems)
* Copy libz3.dll from lib\ to x64\Release\

### Running

* Create the folders `%APPDATA%\Trail of Bits\fuzzkit\working` and `%APPDATA%\Trail of Bits\fuzzkit\log`
* Run `server.exe`
* Create `sample.txt` in the `x64\Release\` directory with at least 8 characters in it
* Run `fuzzkit.exe test_application.exe` from `x64\Release\`
* Run `fuzzkit.exe -r [run_id]` for whatever run id was created for the crash (should be 0 or 1) 
* (This should be in `%APPDATA%\Trail of Bits\fuzzkit\working\[run_id]`)
* Run `triage.exe -r [run_id]` 

### ASM Crash Corpus

* Build `corpus/win_asm`, you'll likely need to change the paths in there
* (Come up with a good solution for this, maybe a config file and Python build script.)
* Run `fuzzkit.exe -t crashes.exe [arg]` for whatever crash you want to check (try 7 write_taint)
* (The above traces without fuzzing for standalone triage)
* Run `triage.exe -r [run_id]` for the run id that was created

## Research questions

```
Fuzzkit
  Code coverage
    How fast can we make single stepping / breakpoints
    How do our alternatives, QEMU, DynamoRIO, Pin perform
      Can we ship these in a single installer?
  Standalone recursive injector / loader (done!)
  Resetting executions (this should be easy!)
    Restore memory and registers (contexts)
      Snapshotting? (memdump maybe?)
    Just spawn a new instance (done!)

Injectable
  Should it contain its own mutation engine as a fallback (talks to server!)
  Does it need initialization (not so far) 
    Run DLLMain
  Get run ID (maybe on DLLMain load?) for reproducibility (done!)

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

