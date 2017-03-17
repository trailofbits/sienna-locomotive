"""
    Pykd script use to retrieve the caller of the current instruction
    Note:
        !py compute_offset_windbg.py Function File Arch
        Where Function is the I/O targeted function, File the input file, and Arch x86 or x64
"""
import sys
import uuid
import pykd

SIZE_INT = 4

# keeping results in hastabl
# avoid several calls to dgbCommand
TARGETED_CALLS_FOUND = {}
MODULES_FOUND = {}
MODULE_OFF_FOUND = {}


def clean_val(val):
    """
    windbg can print 64 bits address  as XXXXX`XXXXX, so we remove the `
    Args:
        val (string): value to clean
    Returns:
        string: cleaned value
    """
    return val.replace('`', '')


def get_filename(func_name, arch):
    """
    Retrieve the filename used
    Args:
        func_name (string): name of the I/O function
    Returns:
    The filename open by the I/O function
    """

    if arch == "x86":
        param = "poi(esp+" + str(1 * SIZE_INT) + ")"
    elif arch == "x64":
        param = "(@rcx)"
    else:
        print "Error arch not supported: " + arch
        return

    if func_name == "CreateFileW":
        file_name = pykd.dbgCommand(
            r'.printf "%mu",' + param)
        file_name = file_name.split("\n")[-1]
        return file_name
    elif func_name == "CreateFileA" or func_name == "fopen":
        file_name = pykd.dbgCommand(
            r'.printf "%ma",' + param)
        file_name = file_name.split("\n")[-1]
        return file_name
    return "NOT_IMPLEM"


def get_targeted_call(line):
    """
    Retrive a call, based on the call stack
    Args:
        depth (int): depth of the call stack
    Returns:
        address targeted

    Algo:
    - retrieve the call stack with kn depth
        example of output
        0:000> kn 2
         # ChildEBP RetAddr
         00 001df9cc 77d80ad8 ntdll!LdrpDoDebuggerBreak+0x2c
         01 001dfb2c 77d65f6f ntdll!LdrpInitializeProcess+0x11aa
    - retrieve the address of thelast "next return adresse"
        In the previous example, it is 77d65f6f
    - use of "ub" (backward dissass) to retrieve the destination of the call
        0:000> ub 77d65f6f L2
        ntdll!_LdrpInitialize+0x70:
        77d65f67 ff7508          push    dword ptr [ebp+8]
        77d65f6a e854130000      call    ntdll!LdrpInitializeProcess (77d672c3)
    - use of L2 (two lines), to avoid errors in the backward dissas
    - return the call
        in the example it is 77d672c3
    """
    global TARGETED_CALLS_FOUND
    targeted_call = line.split(' ')[2]
    targeted_call = clean_val(targeted_call)
    if targeted_call in TARGETED_CALLS_FOUND:
        return TARGETED_CALLS_FOUND[targeted_call]
    targeted_call_index = targeted_call
    print "TARGETED CALL"
    print targeted_call
    targeted_call = pykd.dbgCommand("ub " + targeted_call + " L2")
    targeted_call = targeted_call.split("\n")[-2]
    targeted_call = targeted_call.split(' ')[-1]
    targeted_call = clean_val(targeted_call)
    if targeted_call.endswith(')'):
        targeted_call = targeted_call[:-1]
    if targeted_call.startswith('('):
        targeted_call = targeted_call[1:]
    TARGETED_CALLS_FOUND[targeted_call_index] = targeted_call
    return targeted_call


def get_offset(targeted_call):
    """
    Get the module and offset of an given address
    Args:
        call (string): targeted call
    Returns:
        couple (module,offset)

    Details:
    Use o "lm a", which returns details on the module containing the address
    For example:
        0:000> lm a 77d672c3
        Browse full module list
        start    end        module name
        77d00000 77e42000   ntdll      (pdb symbols)
    offset computed= address-start
    """
    global MODULE_OFF_FOUND
    global MODULES_FOUND
    if targeted_call in MODULE_OFF_FOUND:
        return MODULE_OFF_FOUND[targeted_call]
    lm_res = pykd.dbgCommand("lm a " + targeted_call)
    lm_res = lm_res.split("\n")[-2]
    module = lm_res.split(' ')[4]

    if module in MODULES_FOUND:
        module = MODULES_FOUND[module]
    else:
        module_index = module
        module_res = pykd.dbgCommand("lmv m " + module)
        module_res = module_res.split("\n")
        real_module = [x for x in module_res if "OriginalFilename" in x and (
            ".exe" in x or ".dll" in x)]
        if real_module == []:
            real_module = [x for x in module_res if "Image path" in x]
        if len(real_module) != 0:
            module = real_module[0].split(' ')[-1]
            if "\\" in module:
                module = module[len(module) - module[::-1].index("\\"):]
        MODULES_FOUND[module_index] = module

    start = lm_res.split(' ')[0]
    start = clean_val(start)
    start = int(start.rstrip("L"), 16)
    addr = int(targeted_call, 16)
    computed_off = addr - start
    MODULE_OFF_FOUND[targeted_call] = (module, computed_off)
    return (module, computed_off)

func_name = sys.argv[1]
filename = get_filename(func_name, sys.argv[3])
print "## Func " + func_name
print "## File '" + sys.argv[2] + "'"
if filename.endswith(sys.argv[2]):
    uniq_id = uuid.uuid4().get_hex()
    list_cs = pykd.dbgCommand("kn 100")
    list_cs = list_cs.split("\n")
    # remove warning printed by windbg
    list_cs = filter(lambda x: not x.startswith(
        "WARNING: Stack unwind ") and x != '', list_cs)
    # remove heasder
    list_cs = list_cs[2:]
    i = 0
    for l in list_cs:
        i = i + 1
        try:
            print "## L " + str(l)
            call = get_targeted_call(l)
            print "## Call " + str(call)
            (mod, off) = get_offset(call)
            print "FOUND: #func #" + func_name + "# mod #" + mod + \
                  "# off #" + hex(off).rstrip("L") + "# depth #" + str(i) + \
                "# filename #" + filename + "# uuid #" + uniq_id
        except:
            print "##Error in offset computing"
else:
    print "#Other file: '" + str(filename) + "'"
