"""
    Pykd script use to retrieve the caller of the current instruction
"""
import sys
import pykd

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
    targeted_call = line.split(' ')[2]
    targeted_call = pykd.dbgCommand("ub " + targeted_call + " L2")
    targeted_call = targeted_call.split("\n")[-2]
    targeted_call = targeted_call.split(' ')[-1]
    return targeted_call[1:-1]

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
    start = lm_res.split(' ')[0]
    start = int(start, 16)
    addr = int(targeted_call, 16)
    computed_off = addr - start
    return (module, computed_off)

func_name = sys.argv[1]
try:
    call = get_targeted_call(2)
    (mod, off) = get_offset(call)
    print "FOUND: func " + func_name + " mod " + mod + " off " + hex(off)
except:
    print "##Error in offset computing"
