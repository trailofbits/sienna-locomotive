
#include <Constants.au3>

;
; AutoIt Version: 3.0
; Language:       English
; Platform:       Win7
; Author:         Josselin Feist
;
; Script Function:
;   Opens Sumatra PDF with an input and scrolls three pages.
;

If $CmdLine[0] < 1 Then
	MsgBox($MB_SYSTEMMODAL, "AutoIt", "Run: AutoIt3.exe adobeReaderSimple.au3 test.pdf")
	Exit
EndIf

; Run Sumatra PDF with the input
Run("C:\Program Files\SumatraPDF\SumatraPDF.exe "&$CmdLine[1])

;~ ; Change the method to match windows name > any substring
; see https://www.autoitscript.com/autoit3/docs/functions/AutoItSetOption.htm#WinTitleMatchMode
Opt("WinTitleMatchMode",2)

; Wait for the adobe reader windows
; see https://www.autoitscript.com/autoit3/docs/functions/WinWaitActive.htm
; see https://www.autoitscript.com/autoit3/docs/intro/windowsbasic.htm
$window_handle = WinWaitActive("SumatraPDF")

; scroll three times
sleep(500)
Send("{DOWN 6}{ENTER}")

sleep(500)
Send("{DOWN 6}{ENTER}")

sleep(500)
Send("{DOWN 6}{ENTER}")

sleep(1000)

; check if the window is still open
; write the result in stdout
if(WinExists($window_handle)) Then
   ; ctrl + w, to close the pdf 
   ; Otherwise Sumatra PDF will open the same input at the next execution
   Send("^w")
   WinClose($window_handle)
   ConsoleWrite("no error")
Else
   ConsoleWrite("error")
EndIf

