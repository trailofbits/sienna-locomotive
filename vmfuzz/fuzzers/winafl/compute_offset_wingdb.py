"""
    Pykd script use to retrieve the caller of the current instruction
"""
import sys
import pykd
import uuid

SIZE_INT = 4


def get_filename(func_name):
    if func_name == "CreateFileW":
        filename = pykd.dbgCommand(
            r'.printf "%mu",poi(esp+' + str(1 * SIZE_INT) + ')')
        filename = filename.split("\n")[-1]
        return filename
    elif func_name == "CreateFileA" or func_name == "fopen":
        filename = pykd.dbgCommand(
            r'.printf "%ma",poi(esp+' + str(1 * SIZE_INT) + ')')
        filename = filename.split("\n")[-1]
        return filename
    return "NOT_IMPLEM"


def get_targeted_call(depth):
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
    ret = pykd.dbgCommand("kn " + str(depth))
    line = ret.rstrip().split("\n")[-1]
    print "##line " + line
    targeted_call = line.split(' ')[2]
    print "##Targeted call " + targeted_call
    print "##ub: " + "ub " + targeted_call + " L2"
    targeted_call = pykd.dbgCommand("ub " + targeted_call + " L2")
    print "##Targeted call " + targeted_call
    targeted_call = targeted_call.split("\n")[-2]
    targeted_call = targeted_call.split(' ')[-1]
    targeted_call = targeted_call[1:-1]  # remove the ()
    print targeted_call
    # it is the case if the call is in the form [ ... ()]
    if targeted_call[-1] == ")":
        targeted_call = targeted_call[:-1]
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
    print "##GET OFFSET " + targeted_call
    lm_res = pykd.dbgCommand("lm a " + targeted_call)
    lm_res = lm_res.split("\n")[-2]
    module = lm_res.split(' ')[4]

    module_res = pykd.dbgCommand("lmv m " + module)
    module_res = module_res.split("\n")
    real_module = [x for x in module_res if "OriginalFilename" in x and (".exe" in x or ".dll" in x)]
    if real_module == []:
        real_module = [x for x in module_res if "Image path" in x]
    if len(real_module) != 0:
        module = real_module[0].split(' ')[-1]
        if "\\" in module:
            module = module[len(module) - module[::-1].index("\\"):]

    start = lm_res.split(' ')[0]
    start = int(start, 16)
    addr = int(targeted_call, 16)
    computed_off = addr - start
    return (module, computed_off)

func_name = sys.argv[1]
uniq_id = uuid.uuid4().get_hex()
filename = get_filename(func_name)
try:
    for i in range(2, 20):
        call = get_targeted_call(i)
        print "##CALL " + call
        (mod, off) = get_offset(call)
        print "FOUND: #func #" + func_name + "# mod #" + mod + \
              "# off #" + hex(off) + "# depth #" + str(i) + \
            "# filename #" + filename + "# uuid #" + uniq_id
except:
    print "##Error in offset computing"
