
from triton import *
from pintool import *

# XXX: Edit TRACE_PATH below to point to the generated trace. 
TRACE_PATH = '/home/user/tmp/crash01.trace'

# XXX: List addresses here of the return values of functions
# you want to taint. The example script taints 'rax' after atoi()
# returns, tainting its return value.
RETURN_ADDRS = [0x4009bf, 0x4009df]


import os
import sys
import struct
import StringIO
import capstone

sys.path.append(os.path.dirname(__file__))
import trace_reader
import state
import proc
import exploitable


GREEN = "\033[92m"
ENDC  = "\033[0m"


class LockStep(object):
  '''
    The main class implementing the crash analysis callback
  '''
  class DivergedError(Exception): pass
  
  def __init__(self, tracefile):
    self._tracer = trace_reader.TraceReader(tracefile)
    self._maps = proc.Proc()
    self._state = state.State()
    self._rules = exploitable.Rules
    self._last_instruction = None

  def collect_rules(self):
    'Invokes all heuristic-based rules'
    return [rule_cls().score(self._state) for rule_cls in self._rules]

  def is_address_mapped(self, addr):
    'Ensure that an address is mapped in the client process'
    return not self._maps.find_map_by_address(addr) is None

  def _collect_tainted_registers(self):
    'Return a list of all register names that are currently tainted'
    tainted_registers = []
    for r in dir(REG):
      if not r.startswith('R'):
        continue

      register = getattr(REG, r)

      if not isRegisterTainted(register):
        continue

      tainted_registers.append(register.getName())

    return tainted_registers

  def __call__(self, instruction):
    '''
      The primary analysis callback, called on a per-instruction-executed
      basis.

      Can throw DivergedError if trace diverges from actual execution

    '''
    self._last_instruction = instruction

    if not self._state.stack():
      addr = getRegisterValue(REG.RSP)
      mapping = self._maps.find_map_by_address(addr)
      self._state.set_stack(mapping)

    if not self._maps.find_map_by_address(instruction.getAddress()):
      return

    instr_from_trace = self._tracer.next_instruction()

    if instruction.getAddress() != self._tracer.get_register_value('rip'):
      raise LockStep.DivergedError("Instruction diverged at 0x%x"%(instruction.getAddress(),))

    if not self._tracer.done():
      return

    print "Trace ended; finding taint results"

    self._printTaintResults()

  def _printTaintResults(self):
    'Produce basic output of the current taint information'

    print "Heuristic results: "
    for result in self.collect_rules():
      print "\t", str(result)

    print "Tainted registers: "
    for register in self._collect_tainted_registers():
      print "\t", register

    print "Tainted stack: "
    st = self._state.stack()
    mappings = []
    for b in range(st.address, st.address + st.size):
        if not isMemoryTainted(b):
            continue

        if mappings and mappings[-1][1] == b:
            mappings[-1][1] = b + 1
        else:
            mappings.append([b, b+1])

    for m in mappings:
        print '0x%016x, %d bytes'%(m[0], m[1] - m[0])

    print "Value of RSP: 0x%016x"%(getRegisterValue(REG.RSP),)
    print "Last symbolic expressions: "
    for e in  self._last_instruction.getSymbolicExpressions():
        if e.isTainted():
            print "\t ! %s%s%s"%(GREEN, e.getAst(), ENDC)
        else:
            print '\t ? %s'%(e.getAst(),)

def imageLoad(*args):
    pass
    #print args

def signal(tid, foo):
    #print '--', tid, foo
    pass

###
## This is specific to the client application under analysis.
###
def beforeSymProc(inst):
    # First operand, or rax has the location we need to taint
    if inst.getAddress() in RETURN_ADDRS:
      taintRegister(REG.RAX)
      print "Tainting rax"

def beforeSyscall(sc):
    pass

if __name__ == '__main__':
    # XXX: Edit TRACE_PATH above to point to correct location
    follower = LockStep(TRACE_PATH)

    setupImageBlacklist(['libc', 'ld-linux'])
    setArchitecture(ARCH.X86_64)
    enableTaintEngine(True)
    startAnalysisFromEntry()

    addCallback(follower, CALLBACK.BEFORE)
    addCallback(signal, CALLBACK.SIGNALS)
    addCallback(beforeSymProc, CALLBACK.BEFORE_SYMPROC)
    addCallback(beforeSyscall, CALLBACK.SYSCALL_ENTRY)
    addCallback(imageLoad, CALLBACK.IMAGE_LOAD)

    # Run the instrumentation - Never returns
    runProgram()

