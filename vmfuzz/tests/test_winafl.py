import os
from context import vmfuzz
import fuzzers.winafl.winafl as winafl

os.chdir('..')
winafl.WINAFL_BIN = "afl-fuzz.exe"
winafl.DYNAMORIO_PATH = r"C:\Users\monty\Documents\dynamorio\build\bin32"
winafl.DRRUN = r"C:\Users\monty\Documents\dynamorio\build\bin32\drrun.exe"
winafl.WINAFLDLL = r"C:\Users\monty\winafl\bin32\winafl.dll"

#config_vlc = {'in_dir' : "in",
#          'out_dir' : "out",
#          "timeout" : str(1000*10),
#          "file" : "test.mp3",
#          "module" : "libvlccore.dll",
#          "offset" : "0x93a70",
#          "nargs" : "5"}
#
#running_cmd_vlc = [r'"C:\Program Files\VideoLAN\VLC\vlc.exe"',r"test.mp3"]
#
#cmd = winafl.generate_cmd(config_vlc,running_cmd_vlc)
#print winafl.pp_cmd(cmd)

config_sumatra = {'in_dir': "in",
                  'out_dir': "out2",
                  "timeout": str(1000 * 20),
                  "file": "test.pdf",
                  "module": "SumatraPDF.exe",
                  "offset": "0x170",
                  "nargs": "5",
                  "working_dir":  r"C:\Users\monty\Desktop\test_afl_auto"}
running_cmd_sumatra = [
    r'"C:\Program Files\SumatraPDF\SumatraPDF.exe"', r"test.pdf"]
#cmd = winafl.generate_cmd(config_sumatra,running_cmd_sumatra)
#print winafl.pp_cmd(cmd)
#cmd = winafl.generate_drrun(config_sumatra,running_cmd_sumatra)
#print winafl.pp_cmd(cmd)

winafl.run_winafl(config_sumatra, running_cmd_sumatra)
