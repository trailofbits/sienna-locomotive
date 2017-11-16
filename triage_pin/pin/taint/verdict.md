This document is to record the exploitable / unexploitable verdict decision tree.

## SIGILL

Verdict: Exploitable

Justification: Redirected execution to random data. Likely controls execution pointer.

Thoughts: This isn't really precise.

## SIGFPE 

Verdict: Unexploitable

Justification: Divide by zero.

Thoughts: Are there any exploitable FPE?

## SIGTRAP

Verdict: Unlikely

Justification: Hit a guard that the software author or compiler put in.

## SIGSEGV

### Undecodable instruction

Verdict: Likely

Justification: If we do not have an instruction object associate with the address, we're probably in random data. Likely controls the execution pointer. Also occurs when xed cannot decode the instruction.

### USE AFTER FREE

Verdict: Exploitable

Justification: If the instruction has a UAF flag set from pointer tracking, it is likely exploitable.

Thoughts: Might need to make this a little more precise of R/W/X. Cases where we don't have a vtable? Maybe bump down to likely instead of exploitable. 

### Branching Instruction

Verdict:  

* Taint: Likely

* No taint:  Unlikely

Justification: If we control a crash on an indirect branching instruction, we should control execution pointer. If there is no taint, we probably just caused an error in the program. 

### Return

Verdict: 

* Execution pointer taint: Exploitable

* Stack pointer taint: Exploitable

* Otherwise: Likely

Justification: In the first two cases, we should contorl the return address. The otherwise case indicates stack corruption, but maybe not in a controllable way or in a way that we could not detect / follow. 

### Data execution prevention

Verdict: Likely

Justification: If we are branching to NX memory we are in a similar situation as jumping to random data.

Thoughts: Pin has all memory as `read implies execute`, so we do not get normal DEP crashes. The taint tracking tool compensates this by doing its own DEP tracking. However, using Pin's `IMG_FindByAddress` is unreliable, so the taint tracking is a little generous in its labeling things with the DEP flag.

### Write

Verdict:

* Taint: Likely

* No taint: Unlikely

Justification: Writing controlled data is often exploitable. 

### Read

Verdict:

* Taint: Likely

* No taint: Unlikely

Justification: Reading arbitrary data from the program is useful, maybe not full control but I think it should be ranked as important.

Thoughts: Are tainted reads ever exploitable? Should this be downgraded or is the information disclosure enough to make it `likely`?