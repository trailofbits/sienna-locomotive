Particular behavior details
===========================

**What happens the end of the autoit script and the application**

|                 |   Self-close: autoit script    |  Self-close: application   | Not self-close: autoit script    | Not self-close: application |
|---------        |  ----------------------------  | -------------------------- | ---------------------            | ------------------          |
| Crash detection |  not yet implem                | not yet implem             | check if window is still present | autot-killed by the script  |
| !exploitable    |  exit                          | killed by windbg           | exit                             | killed by windbg            |
| Offset          |  WinWaitClose and exit         | killed by windbg / vmfuzz  | sleep and exit                   | killled by windbg / vmfuzz  |
| winafl          |  WinWaitClose, exit and loop   | killed by winafl           | WinWaitClose, exit and loop      | killed by winafl            |


**Crash Detection and !exploitable Details**

Other methods are used to detect crashes, see [here](exploitability)

**Autoit Behavior Details**

The same user script is used for all runs. 
The behavior is adapted thanks to the autoit library system, see [here](autoit_lib)

**Winafl Details**

More details on winafl can be found [here](fuzzers/winafl)
