#include-once

Func Run_fuzz($cmd) 
    Sleep(4000)
EndFunc

Func Close($window_handle, $prog)
    Sleep(8000)
    Exit(0)
EndFunc

Func Self_close($proc)
EndFunc

Func Sleep_fuzz($sec)
    if ($sec < 2000) then
    	Sleep(2000)
    Else
    	Sleep($sec+2000)
    Endif
EndFunc

Func Send_fuzz($cmd, $proc)
    Sleep(4000)
    Send($cmd)
    Sleep(4000)
EndFunc

