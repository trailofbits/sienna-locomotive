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
    Run($cmd)
EndFunc

Func Close($window_handle, $prog)
    if(_check_alive($window_handle)) Then
        WinClose($window_handle)
        $ret = 0
    Else
	$ret = 1
    EndIf
    Run("Taskkill /IM " & $prog & " /F")
    sleep(500)
    Exit($ret)
EndFunc

Func Self_close($proc)
    MsgBox(0,"", "Not yet implemented")
EndFunc

Func Sleep_fuzz($sec)
    Sleep($sec)
EndFunc

Func Send_fuzz($cmd, $proc)
    ; check that the windows is still active before sending the cmd  
    if(_check_alive($window_handle)) Then
        Send($cmd)
    EndIf
EndFunc

