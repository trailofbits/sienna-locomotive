#include <Constants.au3>
#include "libfuzz.au3"

; Run Sumatra PDF with the input
Run("C:\Program Files\SumatraPDF\SumatraPDF.exe")

$window_handle = WinWaitActive("[CLASS:SUMATRA_PDF_FRAME]")

Send_fuzz("^o",$window_handle)


; ctrl + w, to close the pdf
; Otherwise Sumatra PDF will open the same input at the next execution
Send_fuzz("^w",$window_handle)

Close($window_handle,"SumatraPDF.exe")
