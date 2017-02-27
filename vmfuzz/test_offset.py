# TODO JF : clean file, do something better for testing winafl 
#

import fuzzers.winafl.compute_offset as compute_offset
import fuzzers.winafl.winafl as winafl

compute_offset.WINGDB_PATH = "C:\\Program Files\\Windows Kits\\10\\Debuggers\\x86\\"
compute_offset.WINGDB_SCRIPT = r"E:\\vmfuzz\\fuzzers\\winafl\\compute_offset_wingdb.py"


winafl.WINAFL_PATH = "C:\\Users\\monty\\Desktop\\test_afl_auto\\"
winafl.WINAFL_BIN = "afl-fuzz.exe"
winafl.DYNAMORIO_PATH = r"C:\Users\monty\Documents\dynamorio\build\bin32"
winafl.DRRUN = r"C:\Users\monty\Documents\dynamorio\build\bin32\drrun.exe"
winafl.WINAFLDLL = r"C:\Users\monty\winafl\bin32\winafl.dll"

#print "TEST 7ZIP"
#res = compute_offset.run("C:\\Program Files\\7-Zip\\","7z.exe",
#                  ["-y","e",r"C:\Users\monty\Desktop\dir\test.zip"])
#res = compute_offset.filter_resultats_by_filename(res,"test.zip")
#compute_offseti.print_resultats(res)

#print "TEST SUMATRA"
#res = compute_offset.run("C:\\Program Files\\SumatraPDF\\","SumatraPDF.exe",
#                   [r"C:\Users\monty\Desktop\dir\test-ori.pdf"])
#res = compute_offset.filter_resultats_by_filename(res,"test-ori.pdf")
#compute_offset.print_resultats(res)
#
#prop_winafl = compute_offset.winafl_proposition(res)
#prop_winafl.reverse()
#
#config_sumatra = {'in_dir' : "in",
#          'out_dir' : "out2",
#          "timeout" : str(1000*20),
#          "file" : "test.pdf",
#          "module" : "SumatraPDF.exe",
#          "offset" : "",
#          "working_dir" :  r"C:\Users\monty\Desktop\test_afl_auto",
#          "nargs" : "5"}
#running_cmd_sumatra = [r'"C:\Program Files\SumatraPDF\SumatraPDF.exe"',r"test.pdf"]
#
#for off,mod in prop_winafl:
#    print "Try "+hex(off)
#    config_sumatra['offset']=hex(off)
#    ret = winafl.run_winafl(config_sumatra, running_cmd_sumatra)
#    if(ret==1):
#        break

#for off,mod in prop_winafl:
#    print "##### AFL Proposition ####"
#    config_sumatra['offset']=hex(off)
#    cmd = winafl.generate_drrun_cmd(config_sumatra,running_cmd_sumatra)
#    print winafl.pp_cmd(cmd)
#    cmd = winafl.generate_winafl_cmd(config_sumatra,running_cmd_sumatra)
#    print winafl.pp_cmd(cmd)
#


print "TEST VLC"
res = compute_offset.run("C:\\Program Files\\VideoLAN\\VLC\\", "vlc.exe",
                         [r"C:\Users\monty\Desktop\dir\test-ori.mp3"])
#                     #   [r"--sub-file",r"C:\Users\monty\Desktop\dir\test.txt",r"C:\Users\monty\Desktop\dir\test.wmv"])
res = compute_offset.filter_resultats_by_filename(res, "test-ori.mp3")
compute_offset.print_resultats(res)
prop_winafl = compute_offset.winafl_proposition(res)
prop_winafl.reverse()

config_vlc = {'in_dir': "in_vlc",
              'out_dir': "out2",
              "timeout": str(1000 * 20),
              "file": "test.mp3",
              "module": "vlc.exe",
              "offset": "",
              "working_dir":  r"C:\Users\monty\Desktop\test_afl_auto",
              "nargs": "5"}
running_cmd_vlc = [r'"C:\Program Files\VideoLAN\VLC\vlc.exe"', r"test.mp3"]
#
for off, mod in prop_winafl:
    print "Try " + hex(off) + " at mod " + mod
    config_vlc['offset'] = hex(off)
    config_vlc['module'] = mod
    ret = winafl.run_winafl(config_vlc, running_cmd_vlc)
    if(ret == 1):
        break


#
#print "TEST EASYMP3"
#res = compute_offset.run("C:\\Program Files\\Easy RM to MP3 Converter\\", "RM2MP3Converter.exe", [r""])
#compute_offset.print_resultats(res)

#print "TEST CLAMAV"
#res = compute_offset.run("C:\\Program Files\\ClamAV\\", "clamscan.exe", [r""])
#compute_offset.print_resultats(res)
