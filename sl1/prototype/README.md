
This directory contains three sub-projects: a few crashing samples, a binary
tracer, and a set of Triton scripts.

# crash\_samples

Includes a collection of simple binaries that mostly just crash (crash00 does
not, and is used as a baseline).

Building:

```
 $ mkdir samples_build && cd samples_build
 $ cmake ../crash_samples
 $ make
```

## crash00_nocrash.c
Does not crash. Used as a baseline.

## crash01_stack.c 
Has a simple stack based-overflow.

Usage: `./crash01 0 100`

The program overwrites the stack from index at first parameter to the index
at second parameter. Running `./crash01 0 100` is guaranteed to crash.

## crash02_heap.c
Has a simple heap overflow. Usage is similar to crash01.

## crash03_nullderef.c
Just crashes with a NULL dereference.

## crash04_memaccess.c
Similar to first, but continues writing until it crashes.


# tracer
A binary tracer using the ptrace(2) system call to just execute a binary 
until completion and record the execution state at each instruction. The data
that's produced is later used by Triton scripts.

Building:

Install pre-requisites:
```
 $ sudo apt-get install libboost1.55-all-dev protobuf-compiler libprotobuf-dev
 $ # If running in Linux, might need to enable ptrace first
 $ sudo sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'
```

```
 $ rm -fr tracer_build/ # if was created by earlier commands
 $ mkdir tracer_build && cd tracer_build
 $ cmake ../tracer
 $ make
```

Usage:

```
 $ ./tracer -o ../crash01_trace.out -i ../samples_build/crash01 0 100
 Finished with status: 2
 $ ls -s ../crash01_trace.out 
 32 ../crash01_trace.out
```

# Triton scripts
First, follow instructions to install Triton v0.3 at
 http://triton.quarkslab.com/documentation/doxygen/index.html#install_sec

```
  $ # First, edit the main triton script and set TRACE_PATH to the correct
  $ # file generated above (i.e. /full/path/to/crash01_trace.out)
  $ vi triton/main.py 

  $ PYTHONPATH=build/schema/:tracer/reader ~/path/to/triton/binary/triton triton/main.py samples_build/crash01 0 100
  64
  Tainting rax
  Trace ended; finding taint results
  Heuristic results: 
    0
    Tainted registers: 
    Tainted stack: 
    Value of RSP: 0x00007ffd8adf9548
    Last symbolic expressions: 
       ? (concat ((_ extract 7 0) ref!2565) ((_ extract 7 0) ref!2524) ((_ extract 7 0) ref!2483) ((_ extract 7 0) ref!2442) ((_ extract 7 0) ref!2401) ((_ extract 7 0) ref!2360) ((_ extract 7 0) ref!2319) ((_ extract 7 0) ref!2278))
         ? (bvadd ((_ extract 63 0) ref!4729) (_ bv8 64))
```
  
The script will produce a summary of the crashing state.
