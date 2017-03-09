Winafl: User point of view
=====================================

**Requirements**

- A seed file named "seed.extension" in the directory ```in_program_name``` from the path ```path_winafl_working_dir``` ([system configuration](../../yaml_config/README.md#system-configuration))
    - ex: seed.pdf in in_SumatraPDF
/bin/bash: q: command not found
- The seed file is used to compute offsets, other files presents in the ```in_program_name``` directory are used to fuzz


Winafl: Implementation details
=====================================
Winafl runs on targeted function.
Basically, it executes the function and at its return, it updates the input file and patches ```eip``` to re-execute the function

**Targeted function**

A targeted function is:

- Function containing open / close of the input
- Winafl needs the module name + offset of the function in this module
- Winafl needs the number args of the function
- No side effect is excepted in the function (two runs with the same input are the same)
- For GUI applications, it works if the GUI interactions are not present during the run of the function

**Levels of functions**
```c
f0(char *buf){
	f=open()
	copy(buf,f)
	close(f)
}

f1(){
	char buf[];
	f0()
	do checks on buff
}
```
Both ```f0``` and ```f1``` can be targets, we consider ```f1``` to be __higher__ than ```fo``` (according its call stack)

**Winafl algo to explore all targets**

1. Compute set of possible *(offset,module)*, order them from the *lowest* to the *higher* in the call stack
2. Select the first *(offset,module)* 
3. Run winafl on *(offset,module)* on inputs found in the input directory
4. End winafl if the last new path was found in more than ```winafl_last_path_timeout``` secondes ([system configuration](../../yaml_config/README.md#system-configuration))
5. Move generated inputs to the input directory (remove similar inputs)
6. Select the next *(offset,module)* and go to 3 


The idea is to explore at first the lowest functions and used the generated inputs to help the exploration of higher functions.

(Offset,module) computing
================

**How it works**
- Breakpoints put in I/O functions (fopen / CreationFile)
- When  a breakpoint met, use call stacks to retrieve callers: 
    - Get the next instruction to execute after the ret
    - Dissas backward to retrieve the call instruction
    - Target of the call = offset of the function
- One break = retrieve multiple targets (just go higher in the call stack)

**Details**
Filter the breakpoints according to the argument given to the I/O function (must be = input).

**Pro**
Light and easy to compute

**Con**
Do not work on dynamic calls
Can have errors (wrong call stacks)

**Number of args**
For now, only set the number of args as large one (it should be enough?)
