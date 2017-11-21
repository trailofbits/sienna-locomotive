# Mighty Tasty Fuzzing and Crash Triage

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

## Research questions

```
Fuzzkit
  Code coverage
    How fast can we make single stepping / breakpoints
    How do our alternatives, QEMU, DynamoRIO, Pin
  Standalone recursive injector / loader
  Resetting executions
    Restore memory and registers
      Snapshotting?
    Just spawn a new instance

Injectable
  Should it contain its own mutation engine as a fallback
  Does it need initialization (socket setup) 
    Run DLLMain
  Get run ID (maybe on DLLMain load?) for reproducibility

Mutation Server
  Ideally pluggable with smart stuff (mcore, ai)
  What is the fastest method of interprocess communication
  Smart mutations, file format aware, or code aware
  Needs some state for runs

Tracer
  Fast tracing methods
    IntelPT (special hardware)
    Time travel debugging (no api)
    QEMU (req custom modifications)
    Binary translation
  Identify branches, cache basic blocks for speed
  Proving ground for instrumentation in fuzzkit
  Be able to run in standalone mode

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

Fuzz server
  Unique id per session
    DLLMain to initialize variables / named pipe connection?
    DLLMain could call out to fuzz server when complete which could notify fuzzkit to continue
  Named pipe
    Fork on connection?
  Log data used for each call (reproducibility)
    Per unique run
  Replay mode with data to gather trace, to triage

Taint tracking with Triton
  In replay, at first taint
    Minidump (includes registers?)
    Can one process minidump another? Maybe use user defined exceptions
  In replay, at any taint
    Output buffer and size that is tainted
  Replay trace between first taint and crash
  Set initial register state
  Use minidump for concrete memory values
```

