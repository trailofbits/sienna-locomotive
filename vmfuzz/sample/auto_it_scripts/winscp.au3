#include <Constants.au3>
#include "libfuzz.au3"

; Run Winscp
Run_fuzz("C:\Program Files\WinSCP\WinSCP.exe")

; Wait for the Open windows
; Change Ouvrir to Open in us based windows
$window_handle_login = WinWaitActive("Login")
Sleep_fuzz(500)
ControlClick($window_handle_login, "", "[CLASS:TButton; INSTANCE:1]")
Sleep_fuzz(500)
Send_fuzz("{DOWN}",$window_handle_login)
Sleep_fuzz(500)
Send_fuzz("{DOWN}",$window_handle_login)
Sleep_fuzz(500)
Send_fuzz("{ENTER}",$window_handle_login)
Sleep_fuzz(500)
Send_fuzz("{ENTER}",$window_handle_login)
Sleep_fuzz(500)
Send_fuzz("C:\Users\monty\Desktop\test_afl_auto\in_winscp\test.ini",$window_handle_login)
Sleep_fuzz(500)
Send_fuzz("{ENTER}",$window_handle_login)

;Send_fuzz($CmdLine[1], $window_handle)
;exit(0)
; Clic on Load button
;ControlClick($window_handle_open, "", "[CLASS:Button; INSTANCE:2]")

;Sleep_fuzz(1000)

;Close($window_handle,"RM2MP3Converter.exe")

