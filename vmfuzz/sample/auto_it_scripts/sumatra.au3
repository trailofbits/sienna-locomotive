#include <Constants.au3>
#include "libfuzz.au3"

; Run Sumatra PDF with the input
Run("C:\Program Files\SumatraPDF\SumatraPDF.exe "&$CmdLine[1])
start()

$window_handle = WinWaitActive("[CLASS:SUMATRA_PDF_FRAME]")

; scroll three times
Sleep_fuzz(500)
Send_fuzz("{DOWN 6}{ENTER}",$window_handle)

Sleep_fuzz(500)
Send_fuzz("{DOWN 6}{ENTER}",$window_handle)

Sleep_fuzz(500)
Send_fuzz("{DOWN 6}{ENTER}",$window_handle)

Sleep_fuzz(1000)

; ctrl + w, to close the pdf
; Otherwise Sumatra PDF will open the same input at the next execution
Send_fuzz("^w",$window_handle)

Close($window_handle,"SumatraPDF.exe")
