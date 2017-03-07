#include-once

; check if the window is still open
Func _check_alive($window_handle)
    if(WinExists($window_handle)) Then
        Return True
    Else
        Return False
    EndIf
EndFunc


Func Run_fuzz($cmd)
EndFunc

Func Close($window_handle, $prog)
    WinWaitClose($window_handle)
    Exit(0)
EndFunc

Func Self_close($proc)
EndFunc

Func Sleep_fuzz($sec)
    if ($sec < 1000) then
    	Sleep(2000)
    Else
    	Sleep($sec+2000)
    Endif
EndFunc

Func Send_fuzz($cmd, $proc)
    ; check that the windows is still active before sending the cmd  
    if(_check_alive($window_handle)) Then
    	Sleep(2000)
        Send($proc, $cmd)
    	Sleep(2000)
    EndIf
EndFunc

