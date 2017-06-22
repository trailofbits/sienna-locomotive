import sys
from manticore import Manticore
# sys.path.append('/home/taxicat/work/binja/binaryninja/python/')
# import binaryninja as binja

debug = True
count = 0

MAX_PATH = 300
NULL = '\x00'

# Syscall numbers for hooking
SYS_READ = 0
SYS_OPEN = 2
SYS_CLOSE = 3

# Just going to map any register to full width 
reg_map = {
    # RAX
    'AH': 'RAX',
    'AL': 'RAX',
    'AX': 'RAX',
    'EAX': 'RAX',
    'RAX': 'RAX',
    # RBX
    'BH': 'RBX',
    'BL': 'RBX',
    'BX': 'RBX',
    'EBX': 'RBX',
    'RBX': 'RBX',
    # RCX
    'CH': 'RCX',
    'CL': 'RCX',
    'CX': 'RCX',
    'ECX': 'RCX',
    'RCX': 'RCX',
    # RDX
    'DH': 'RDX',
    'DL': 'RDX',
    'DX': 'RDX',
    'EDX': 'RDX',
    'RDX': 'RDX',
    # RSI
    'SIL': 'RSI',
    'SI': 'RSI',
    'ESI': 'RSI',
    'RSI': 'RSI',
    # RDI
    'DIL': 'RDI',
    'DI': 'RDI',
    'EDI': 'RDI',
    'RDI': 'RDI',
    # RSP
    'SPL': 'RSP',
    'SP': 'RSP',
    'ESP': 'RSP',
    'RSP': 'RSP',
    # RBP
    'BPL': 'RBP',
    'BP': 'RBP',
    'EBP': 'RBP',
    'RBP': 'RBP',
    # R8
    'R8B': 'R8',
    'R8W': 'R8',
    'R8D': 'R8',
    'R8': 'R8',
    # R9
    'R9B': 'R9',
    'R9W': 'R9',
    'R9D': 'R9',
    'R9': 'R9',
    # R10
    'R10B': 'R10',
    'R10W': 'R10',
    'R10D': 'R10',
    'R10': 'R10',
    # R11
    'R11B': 'R11',
    'R11W': 'R11',
    'R11D': 'R11',
    'R11': 'R11',
    # R12
    'R12B': 'R12',
    'R12W': 'R12',
    'R12D': 'R12',
    'R12': 'R12',
    # R13
    'R13B': 'R13',
    'R13W': 'R13',
    'R13D': 'R13',
    'R13': 'R13',
    # R14
    'R14B': 'R14',
    'R14W': 'R14',
    'R14D': 'R14',
    'R14': 'R14',
    # R15
    'R15B': 'R15',
    'R15W': 'R15',
    'R15D': 'R15',
    'R15': 'R15',
}

def handle_open(m, state):
    '''
    Handle the open syscall.

    Checks if target file name is contained in the path
    that is passed to open. If it is, it saves the file
    descriptor as the target.
    '''
    cpu = state.cpu
    path_ptr = cpu.RDI
    path = cpu.read_bytes(path_ptr, MAX_PATH)

    if NULL in path:
        idx_null = path.index(NULL)
        path = ''.join(path[:idx_null])

    if m.context['target_file'] in path:
        pc_next = cpu.RIP + cpu.instruction.size
        @m.hook(pc_next)
        def get_fd(state):
            cpu = state.cpu
            m.context['target_fd'] = cpu.RAX

def handle_read(m, state):
    '''
    Handle the read syscall.

    If the target file descriptor is being read, it
    taints the memory that is being read into.
    '''
    cpu = state.cpu
    fd = cpu.RDI
    buf = cpu.RSI
    count = cpu.RDX

    if m.context['target_fd'] == fd:
        print '*** COUNT', count
        pc_next = cpu.RIP + cpu.instruction.size
        @m.hook(pc_next)
        def check_count(state):
            cpu = state.cpu
            count = cpu.RAX
            taint = []
            for i in xrange(count):
                taint.append(buf+i)

            taint_addrs(m, taint)
            print '*** CHECK', count

def handle_close(m, state):
    '''
    Handle the close syscall.

    If the target file is being closed, remove the file descriptor.
    '''
    cpu = state.cpu
    fd = cpu.RDI

    if m.context['target_fd'] == fd:
        m.context['target_fd'] = -1

def taint_addr(m, addr):
    '''
    Add a single address to tainted memory.
    '''
    if addr not in m.context['taint_mem']:
        print '*** TAINTING MEM', hex(addr)
        taint_mem = m.context['taint_mem']
        taint_mem.add(addr)
        m.context['taint_mem'] = taint_mem

def taint_addrs(m, addrs):
    '''
    Add multiple addresses to tainted memory.
    '''
    print '*** TAINTING MEM', hex(addrs[0]), hex(addrs[-1])
    m.context['taint_mem'] = m.context['taint_mem'].union(set(addrs))

def untaint_addr(m, addr):
    '''
    Remove an address from tainted memory.
    '''
    taint_mem = m.context['taint_mem']
    if addr in taint_mem:
        print '*** UNTAINTING MEM', hex(addr)
        taint_mem.remove(addr)
        m.context['taint_mem'] = taint_mem

def taint_reg(m, reg):
    '''
    Mark a register as tainted.
    '''
    if reg not in m.context['taint_reg']:
        print '*** TAINTING REG', reg
        taint_reg = m.context['taint_reg']
        taint_reg.add(reg)
        m.context['taint_reg'] = taint_reg

def untaint_reg(m, reg):
    '''
    Untaint a register.
    '''
    if reg in m.context['taint_reg']:
        print '*** UNTAINTING REG', reg
        taint_reg = m.context['taint_reg']
        taint_reg.remove(reg)
        m.context['taint_reg'] = taint_reg

def map_reg(reg):
    '''
    Map a regsiter to its full width version if available.
    '''
    if reg in reg_map:
        return reg_map[reg]
    return reg

# TODO consider size
def handle_mov(m, state):
    '''
    Handle the mov instruction.

    Checks whether the source memory or register is tainted 
    and taints or untaints the destination appropriately.
    '''
    cpu = state.cpu
    insn = cpu.instruction

    if insn.operands[0].type == 'memory' and insn.operands[1].type == 'register':
        addr = insn.operands[0].address()
        reg = map_reg(insn.operands[1].reg)
        
        if reg in m.context['taint_reg']:
            taint_addr(m, addr)
        else:
            untaint_addr(m, addr)

    elif insn.operands[0].type == 'register' and insn.operands[1].type == 'memory':
        reg = map_reg(insn.operands[0].reg)
        addr = insn.operands[1].address()

        if addr in m.context['taint_mem']:
            taint_reg(m, reg)
        else:
            untaint_reg(m, reg)

    elif insn.operands[0].type == 'register' and insn.operands[1].type == 'register':
        reg0 = map_reg(insn.operands[0].reg)
        reg1 = map_reg(insn.operands[1].reg)

        if reg1 in m.context['taint_reg']:
            taint_reg(m, reg0)
        else:
            untaint_reg(m, reg0)

def handle_lea(m, state):
    '''
    Handle the lea instruction.

    If the base or index of the lea calculation is tainted,
    then taint the destination register.
    '''
    cpu = state.cpu
    insn = cpu.instruction

    # print hex(cpu.RIP), insn.mnemonic, insn.op_str
    # print insn.operands[1].mem.base
    # print insn.operands[1].mem.index
    # print insn.operands[0].reg
    # print

    base = insn.operands[1].mem.base
    index = insn.operands[1].mem.index
    dest = map_reg(insn.operands[0].reg)
    tainted = False

    if base is not None:
        base = map_reg(base)
        if base in m.context['taint_reg']:
            taint_reg(m, dest)
            tainted = True

    if index is not None and not tainted:
        index = map_reg(index)
        if index in m.context['taint_reg']:
            taint_reg(m, dest)
            tainted = True

    if not tainted:
        untaint_reg(m, dest)

def is_tainted(m, op):
    '''
    Checks whether an instruction operand is tainted.
    '''
    if op.type == 'register' and map_reg(op.reg) in m.context['taint_reg']:
        return True
    elif op.type == 'memory' and op.address() in m.context['taint_mem']:
        return True

    return False

def handle_math(m, state):
    '''
    Handle add, sub, or, xor, and and instructions.
    '''
    cpu = state.cpu
    insn = cpu.instruction

    reg = map_reg(insn.operands[0].reg)
    op = insn.operands[1]

    if is_tainted(m, op):
        taint_reg(m, reg)
    else:
        untaint_reg(m, reg)

def handle_hard_math(m, state):
    '''
    Handle mul and div instructions.
    '''
    cpu = state.cpu
    insn = cpu.instruction
    op_cnt = insn.op_count

    if op_cnt == 1:
        if is_tainted(insn.operands[0]):
            taint_reg(m, 'RAX')
            taint_reg(m, 'RDX')
        else:
            untaint_reg(m, 'RAX')
            untaint_reg(m, 'RDX')
    elif op_cnt == 2:
        if is_tainted(insn.operands[1]):
            taint_reg(m, insn.operands[0].reg)
        else:
            untaint_reg(m, insn.operands[0].reg)
    elif op_cnt == 3:
        if is_tainted(insn.operands[1]) or is_tainted(insn.operands[2]):
            taint_reg(m, insn.operands[0].reg)
        else:
            untaint_reg(m, insn.operands[0].reg)

def dump_taint(m, state):
    '''
    Print the tainted state.
    '''
    print 'TAINTED REGS ==='
    for reg in m.context['taint_reg']:
        print reg, hex(state.cpu.__getattr__(reg))
    print

    print 'TAINTED MEM ==='
    mem = sorted(list(m.context['taint_mem']))
    start = mem[0]
    end = mem[0]

    for idx in xrange(1, len(mem)):
        if mem[idx] - mem[idx-1] == 1:
            end = mem[idx]
        else:
            if start != end:
                print '%s to %s' % (hex(start), hex(end))
            else:
                print hex(start)
            
            start = mem[idx]
            end = mem[idx]

    if start != end:
        print '%s to %s' % (hex(start), hex(end))
    else:
        print hex(start)
    print

def insn_hook(m):
    '''
    Hook every instruction and call the appropriate instruction handler.
    '''
    sys_lookup = {
        SYS_READ: handle_read,
        SYS_OPEN: handle_open,
        SYS_CLOSE: handle_close
    }

    @m.hook(None)
    def insn(state):
        cpu = state.cpu
        insn = cpu.instruction
        insn_name = insn.insn_name()

        if insn_name in ['mov', 'movsx', 'movzx', 'movbe']:
            handle_mov(m, state)
        elif insn_name in ['add', 'sub', 'or', 'xor', 'and']:
            handle_math(m, state)
        elif insn_name in ['mul', 'imul', 'div', 'idiv']:
            handle_hard_math(m, state)
        elif insn_name == 'lea':
            handle_lea(m, state)
        elif insn_name == 'syscall':
            # rdi, rsi, rdx, r10, r8, r9
            if cpu.RAX in sys_lookup:
                sys_lookup[cpu.RAX](m, state)

        # instruction dump
        if len(m.context['taint_mem']) > 0 or len(m.context['taint_reg']) > 0:
            print hex(cpu.RIP), insn.mnemonic, insn.op_str

    # @m.hook(0x4006f2)
    # def examine(state):
    #     cpu = state.cpu
    #     insn = cpu.instruction
    #     print hex(cpu.RBP)
    #     print insn.operands[0].type
    #     print insn.operands[1].type
    #     print hex(insn.operands[1].address())
    #     print m.context['taint_reg']

    @m.hook(0x400666)
    def start_print(state):
        '''
        Add taint to being instruction dump.
        '''
        taint_addr(m, 0x1337)

    @m.hook(0x4006f9)
    def check_mem(state):
        '''
        Check taint at specific comparison.
        '''
        print state.cpu
        dump_taint(m, state)

def main():
    if len(sys.argv) < 3:
        print 'USAGE: python %s target_program taint_file' % sys.argv[0]
        sys.exit()

    path = sys.argv[1]
    m.context['target_file'] = sys.argv[2]
    m = Manticore(path)

    m.context['target_fd'] = -1
    m.context['taint_reg'] = set()
    m.context['taint_mem'] = set()

    m.verbosity = 2

    insn_hook(m)

    m.run()

if __name__ == '__main__':
    main()