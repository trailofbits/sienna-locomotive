Add these: https://github.com/jfoote/exploitable/blob/master/exploitable/lib/rules.py

# Exploitable 

## If executing from the stack 
  
* Know stack range
* Examine PC
* Check address

## If a DEP violation is hit in user mode (if not near NULL) 

* Know stack range
* Check if PC is on stack?
* Check address
* TODO: Cause DEP violation, see which instruction it ends on 

## If a guard page violation is hit 

* Hook malloc 
* Add guard pages

## Heap corruption, UAF

* Hook malloc
* Hook free
* Track allocated areas and make sure writes are bounded

## If an access violation is hit in user mode (if not near NULL) 

* Examine instruction
* Determine read, write, or execute

## If write violation in user space memory and not near null 

* Examine instruction
* Determine read, write, or execute

## If access violation on a control flow instruction in user mode (if not near NULL) 

Calls, branches, returns

* Examine instruction
* Determine control flow
* Check address

## If executing from user space, but in kernel mode 

* Check if executing in kernel (protected?) mode

## If executed an illegal instruction 
  
* ???

## If a privileged instruction exception is hit 

* ???

## If the stack is overrun 

* ???

## If a DEP violation is hit in kernel mode 

* ???

## If an access violation is hit at the in kernel mode 

* ???

## If the exception chain is corrupted 

* ???

## If write violation in kernel memory from kernel code 

* ???

## If second chance write violation in kernel code 

* ???

----

# Likely Exploitable

## Try disassembling the instruction, if can't 

* Use a disassembler (intelxed?)

## If locally "tainted" data is used to control branch target 

* Examine instruction
* Determine control flow
* Examine taint of destination operand

## If locally "tainted" data is used to control write 

* Examine instruction
* Determine write

## If read access violation on a block data move 

* ???

## If access violation on a control flow instruction in user mode 

* Duplicated above

## DEP violation in user mode (if not near NULL) 

* Duplicated above

----

# Likely Unexploitable

## If read access violation (if not near NULL) 

* Examine instruction
* Determine read
* Check address

## Divide by zero 

* Examine instruction
* Check if math

## Stack exhaustion 

* ???

## If first chance exception for access violation, of kernel code to user memory 

* ???

----

# Unknown

## All user mode write access violations (if near NULL) 

* Examine instruction
* Determine read
* Check address

## Breakpoints are probably not 

* Examine instruction
* Check CCh

## Bug checks (BSOD) 

* ???

## If the stack contains unknown functions 

* ???

## If access violation (read) in kernel mode 

* ???

## Other influence from locally­tainted data

* ???

## If application verifier stops 

* ???
