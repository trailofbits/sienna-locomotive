AutoIT script
=============

List of autoit functions:
https://www.autoitscript.com/autoit3/docs/functions.htm

In the following:
- ```$window_handle``` is the handle of the main window (which can be returned by ```WinWait```)
- ```$prog_name``` is the program name

**Wrappers**
- ```Send(keys)``` -> ```Send_fuzz(keys,$window_handle)```
- ```Sleep(time)``` -> ```Sleep_fuzz(time,$window_handle)```

**Rules**
- Must include ```"libfuzz.au3"```
- The input file is passed through ```$CmdLine[1]```
- Call ```start()``` once the application is launched
- Call ```self_close($window_handle,$prog_name)``` at the end of the script for self closing application
- Call ```close($window_handle,$prog_name)``` at the end of the script if the application does not close itself
- Forbid side effects (two runs must be similar)

**Script example** 

```
#include <Constants.au3>
#include "libfuzz.au3"

; Run the program with the input
Run("program.exe " & $CmdLine[1])
start()

$window_handle = WinWaitActive("my program")

; do stuff

self_close($window_handle,"program.exe")
```

