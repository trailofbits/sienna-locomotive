#include <Constants.au3>
#include "libfuzz.au3"

; Run Easy RM to MP3
Run_fuzz("C:\Program Files\Easy RM to MP3 Converter\RM2MP3Converter.exe")

$window_handle = WinWaitActive("Easy RM to MP3 Converter")

; Clic on Load button (see AutoIv Window info to know ID numbers)
ControlClick($window_handle, "", "[ID:1001]")

; Wait for the Open windows
; Change Ouvrir to Open in us based windows
$window_handle_open = WinWaitActive("Open")
Send_fuzz($CmdLine[1], $window_handle)

; Clic on Load button 
ControlClick($window_handle_open, "", "[CLASS:Button; INSTANCE:2]")

Sleep_fuzz(1000)

Close($window_handle,"RM2MP3Converter.exe")
