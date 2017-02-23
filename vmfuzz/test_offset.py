import compute_offset

compute_offset.WINGDB_PATH = "C:\\Program Files\\Windows Kits\\10\\Debuggers\\x86\\"
compute_offset.WINGDB_SCRIPT = r"E:\\vmfuzz\\compute_offset_wingdb.py"

print "TEST SUMATRA"
res = compute_offset.run("C:\\Program Files\\SumatraPDF\\","SumatraPDF.exe", 
                   [r"C:\Users\monty\Desktop\dir\test.pdf"])
compute_offset.print_resultats(res)
#print "TEST VLC"#
#res = compute_offset.run("C:\\Program Files\\VideoLAN\\VLC\\", "vlc.exe",
#              [r"C:\Users\monty\Desktop\dir\test.mp3"])
#compute_offset.print_resultats(res)#
#
#print "TEST EASYMP3"
#res = compute_offset.run("C:\\Program Files\\Easy RM to MP3 Converter\\", "RM2MP3Converter.exe", [r""])
#compute_offset.print_resultats(res)
#
#print "TEST CLAMAV"
#res = compute_offset.run("C:\\Program Files\\ClamAV\\", "clamscan.exe", [r""])
#compute_offset.print_resultats(res)
