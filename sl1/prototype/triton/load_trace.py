
import ctypes

from triton import *
from pintool import *

import sys
import os
filename = os.path.join(os.path.dirname(__file__), "../../tracer/reader")
print "Adding %s to search path\n(__file__=%s)" %(filename,__file__)
print open('/proc/self/cmdline').read()
sys.path.append(filename)

import tracer
import proc

image = None

# [sys.stdout.write(k + "," + str(v) +"\n") for (k,v) in sys.modules.items()]

# sys.exit(0)

# 0x40058b: movzx eax, byte ptr [rax]
#
# When the instruction located in 0x40058b is executed,
# we taint the memory that RAX holds.
def cbeforeSymProc(instruction):
    if instruction.getAddress() == 0x40058b:
        rax = getRegValue(IDREF.REG.RAX)
        taintMem(rax)

def cbefore(instruction):
    #print image
    #print t.state().dump()
    print hex(t.state().pc())
    if (t.state().pc() >= image[1]) and (t.state().pc() < image[1] + image[2]):
        next(t)
    else:
        return
    print '%#x: %s' %(instruction.getAddress(), instruction.getDisassembly())
    #print t.state().dump()
    # for se in instruction.getSymbolicExpressions():
    #     if se.isTainted() == True:
    #         print '\t -> %s%s%s' %(GREEN, se.getAst(), ENDC)
    #     else:
    #         print '\t -> %s' %(se.getAst())
    print


def onImageLoad(path, base, size):
    global image
    if not image:
        image = (path, base, size)


if __name__ == '__main__':
    s = open('trace', 'r')
    t = tracer.ExecutionTrace(s)

    # Start the symbolic analysis from the 'check' function
    startAnalysisFromEntry()

    setArchitecture(ARCH.X86_64)

    addCallback(onImageLoad, CALLBACK.IMAGE_LOAD)

    addCallback(cbeforeSymProc, CALLBACK.BEFORE_SYMPROC)

    addCallback(cbefore, CALLBACK.BEFORE)

    # Run the instrumentation - Never returns
    runProgram()

