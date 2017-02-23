#include <Constants.au3>

;
; AutoIt Version: 3.0
; Language:       English
; Platform:       Win7
; Author:         Josselin Feist
;
; Script Function:
;   Open Easy Rm MP3 Convertor, cllique on Open, and load the m3u file.
;

If $CmdLine[0] < 1 Then
	MsgBox($MB_SYSTEMMODAL, "AutoIt", "Run: AutoIt3.exe easyRmToMp3Converter.au3 path\to\test.m3u")
	Exit
EndIf

; Run Easy RM to MP3
Run("C:\Program Files\Easy RM to MP3 Converter\RM2MP3Converter.exe")

;~ ; Change the method to match windows name > any substring
; see https://www.autoitscript.com/autoit3/docs/functions/AutoItSetOption.htm#WinTitleMatchMode
Opt("WinTitleMatchMode",2)

; Wait for the adobe reader windows
; see https://www.autoitscript.com/autoit3/docs/functions/WinWaitActive.htm
; see https://www.autoitscript.com/autoit3/docs/intro/windowsbasic.htm
$window_handle = WinWaitActive("Easy RM to MP3 Converter")

; Clic on Load button (see AutoIv Window info to know ID numbers)
ControlClick($window_handle, "", "[ID:1001]")

; Change Ouvrir to Open in us based windows
sleep(500)
Send($CmdLine[1])


; Clic on Load button (see AutoIv Window info to know ID numbers)
$window_handle_open = WinWaitActive("Open")
ControlClick($window_handle_open, "", "[CLASS:Button; INSTANCE:2]")

sleep(500)
 ;check if the window is still open
 ;write the result in stdout
if(WinExists($window_handle)) Then
   WinClose($window_handle)
   ConsoleWrite("no error")
Else
   ConsoleWrite("error")
EndIf

; Kill the application to kill all possible dialog boxes
Run("Taskkill /IM RM2MP3Converter.exe /F")
sleep(100)
