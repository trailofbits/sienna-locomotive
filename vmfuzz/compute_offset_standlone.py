""" Module handling !exploitable (without GUI interaction)
    !exploitable dll (MSEC.dll) has to be installed in
    DEBUG_PATH\\winext
    Example:
    C:\\Program Files\\Windows Kits\\10\\Debuggers\\x86\\winext"
    or
    C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\winext"
    """

import subprocess
import os

SIZEOFCALL=5

WINGDB_PATH = ""
# cdb.exe: user mode debuger with command line interface
DEBUG = "cdb.exe"

# Run the program, load the MSEC dll, run !exploitable and quit
#WINGDB_CMD = r'bp kernel32!CreateFileW "r $t0 = 0;.foreach (v { kn 3 }) { .if ($spat(\"v\", \"*SumatraPDF*\")) {r $t0 = 1;.echo \'START_BT\';k 3;.echo \'CLOSE_BT\';gc} }; .if($t0 = 0) { gc }";'
#WINGDB_CMD = r'bp kernel32!CreateFileW;g'

WINGDB_PATH = "C:\\Program Files\\Windows Kits\\10\\Debuggers\\x86\\"

def make_wingdb_cmd(module,function,module_caller,depth):
    return r'bp '+module+'!'+function+r' "r $t0 = 0;.foreach (v { kn '+depth+r' }) { .if ($spat(\"v\", \"*'+module_caller+r'*\")) {r $t0 = 1;.echo \'START_BT'+function+r'\';k 3;.echo \'CLOSE_BT'+function+r'\';gc} }; .if($t0 = 0) { gc }"' 


def run(path_program, program_name, parameters,module,func,caller):
    """
    Run !exploitable
    Args:
        path_program (string): path the to the program
        program_name (string): name of the program
        parameters (string list): parameters of the script
    Returns:
        string: exploitability verdict
    """
    wingdb_cmd = make_wingdb_cmd(module,func,caller,str(3))
#    wingdb_cmd = wingdb_cmd + ";" + make_wingdb_cmd("kernel32","CreateFileW","libmupdf",str(3))
    wingdb_cmd = wingdb_cmd + ";gc;q"
    cmd = [WINGDB_PATH + DEBUG, "-c", wingdb_cmd, os.path.join(path_program, program_name)] + parameters
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    print "PROCESS LAUNCHED"
    first =False
    found=[]
    in_bt=False
    for line in iter(proc.stdout.readline, b''):
        print line
        if first:
            proc.stdin.write("gc\n")
            first=False
        if line.startswith("'CLOSE_BT"):
            print "Close found"
            found=found+[(prev,line.rstrip()[9:][:-1])]
            in_bt=False
        if line.startswith("'START_BT"):
            in_bt=True
        if in_bt:
            prev=line
    print "PROCESS ENDED"
    to_compute = ["u "+x.split(' ')[2][:-1]+"-"+str(SIZEOFCALL)+" L1" for (x,y) in found]
    functions_list = [y for (x,y) in found]
    wingdb_cmd2 = ";".join(to_compute)+";q"
    cmd = [WINGDB_PATH + DEBUG, "-c", wingdb_cmd2, os.path.join(path_program, program_name)] + parameters
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    found=[]
    print cmd
    for line in iter(proc.stdout.readline, b''):
        print line
        if "call" in line:
            found=found+[line]
    found = [x.split(' ')[11] for x in found]
    found = [x.split("+") for x in found]
    if len(found) != len(functions_list):
        print "Some functions are missing"
        exit(0)
    found = [x+[module_name] for module_name, x in zip(functions_list,found)]
    for mod,off,func in found:
        print mod+" "+off+" ("+func+")"

#run("C:\\Program Files\\SumatraPDF\\","SumatraPDF.exe", 
#              [r"C:\Users\monty\Desktop\dir\test.pdf"],"kernel32","CreateFileW","SumatraPDF")

run("C:\\Program Files\\VideoLAN\\VLC\\", "vlc.exe",
              [r"C:\Users\monty\Desktop\dir\test.mp3"],"kernel32","CreateFileW","vlc")
