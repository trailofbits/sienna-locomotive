Writing AutoIT script
===============

The script-based language  [AutoIT](https://www.autoitscript.com/site/autoit/) is used to automatize GUI interactions.

VMfuzz needs AutoIt scripts to follow a set of rules.


In the following:
- ```$window_handle``` is the handle of the main window (which can be returned by ```WinWait```)
- ```$prog_name``` is the program name

**Rules**
- The script must include ```"libfuzz.au3"```
- The input file is passed through ```$CmdLine[1]```
- The program is called using ```Run_fuzz()```
- Call ```self_close($window_handle, $prog_name)``` at the end of the script for self closing application
- Call ```close($window_handle, $prog_name)``` at the end of the script if the application does not close itself
- Forbid side effects (two runs must be similar)

Instead of using the original [AutoIT functions](https://www.autoitscript.com/autoit3/docs/functions.htm), use the following set of wrappers:

**Wrappers**
- ```run($cmd)``` ->  ```Run_fuzz($cmd) ```
- ```Send($keys)``` -> ```Send_fuzz($keys, $window_handle)```
- ```SendKeepActive($keys)``` -> ```SendKeepActive_fuzz($keys, $window_handle)```
- ```ControlSend($title, $text, $controlid, $string)``` -> ```ControlSend_fuzz($title, $text, $controlid, $string, $window_handle)```
- ```ControlCommand($title, $text, $controlid, $command)``` -> ```ControlCommand_fuzz($title, $text, $controlid, $command, $window_handle)```
- ```Send($keys)``` -> ```Send_fuzz($keys, $window_handle)```
- ```Sleep($time)``` -> ```Sleep_fuzz($time, $window_handle)```


**Minimal Script Example** 

```
#include <Constants.au3>
#include "libfuzz.au3"

; Run the program with the input
Run_fuzz("program.exe " & $CmdLine[1])

$window_handle = WinWaitActive("my program")

; do stuff

self_close($window_handle, "program.exe")
```

More examples can be found [here](../sample/auto_it_scripts).

How it works (developer)
=======================

According to the type running, the proper ```libfuzz.au3``` is selected:

- ```libfuzz.au3``` to be used on normal run (radamsa)
- ```exploitable\libfuzz.au3``` is used by !exploitable
- ```offset\libfuzz.au3``` is used by the offset computing system (based on windbg)
- ```winafl\libfuzz.au3``` is used by winafl


The same user script is run, but the behavior is changed thanks to the library.
Examples of changes:
- ```Run_fuzz()``` launches the binary only on normal runs (and does nothing for the other runs)
- Several call to sleep() are added; otherwise the original script would be too fast for slow runs (such as under windbg)
