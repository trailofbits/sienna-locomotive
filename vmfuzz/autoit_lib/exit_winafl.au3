Opt("WinTitleMatchMode",2)
if WinExists("WinAFL Notice") Then
   $window_handle = WinWait("WinAFL Notice")
   ControlClick($window_handle, "", "[CLASS:Button; INSTANCE:1]")
Endif
