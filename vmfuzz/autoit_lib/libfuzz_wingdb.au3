#include-once

Func Run_fuzz($cmd)
EndFunc

Func Close($window_handle, $prog)
EndFunc

Func Self_close($proc)
EndFunc

Func Sleep_fuzz($sec)
    Sleep($sec*10000)
EndFunc

Func Send_fuzz($cmd, $proc)
    Sleep(1000)
    Send($cmd)
EndFunc

