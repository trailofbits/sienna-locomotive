#include-once

#include <AutoItConstants.au3>

Func Run_fuzz($cmd) 
    Sleep(4000)
EndFunc

Func Close($window_handle, $prog)
    Sleep(8000)
    Exit(0)
EndFunc

Func Self_close($window_handle)
    WinWaitClose($window_handle)
    Exit(0)
EndFunc

Func Sleep_fuzz($sec)
    if ($sec < 2000) then
    	Sleep(2000)
    Else
    	Sleep($sec+2000)
    Endif
EndFunc

Func Send_fuzz($keys, $window_handle)
    WinSetOnTop($window_handle, "", $WINDOWS_ONTOP)
    Sleep(4000)
    Send($keys)
    Sleep(4000)
EndFunc

Func SendKeepActive_fuzz($keys, $window_handle)
    WinSetOnTop($window_handle, "", $WINDOWS_ONTOP)
    Sleep(4000)
    SendKeepActive($keys)
    Sleep(4000)
EndFunc

Func ControlSend_fuzz($title, $text, $controlid, $string, $window_handle)
    WinSetOnTop($window_handle, "", $WINDOWS_ONTOP)
    Sleep(4000)
    ControlSend($title, $text, $controlid, $string)
    Sleep(4000)
EndFunc

Func ControlCommand_fuzz($title, $text, $controlid, $command, $window_handle)
    WinSetOnTop($window_handle, "", $WINDOWS_ONTOP)
    Sleep(4000)
    ControlCommand($title, $text, $controlid, $command)
    Sleep(4000)
EndFunc
