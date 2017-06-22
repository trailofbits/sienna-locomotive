import sys
from manticore import Manticore

# Syscall numbers for hooking
SYS_READ = 0
SYS_OPEN = 2
SYS_CLOSE = 3

MAX_PATH = 300
NULL = '\x00'

def gather_trace(prog, params):
    print "Gathering trace..."

    m = Manticore(prog, params)
    # 'trace' will contain the executed instructions

    # None: The hook will be applied to all the instructions
    @m.hook(None)
    def record_trace(state):
        pc = state.cpu.PC
        # Store the address of the instruction
        with open('trace.txt', 'a') as f:
            f.write(str(pc) + '\n')

    m.run()

    # Print number of instructions recorded
    print "%d instructions are recorded" % len(trace)

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
            symbolic_buffer = state.new_symbolic_buffer(count)
            state.cpu.write_bytes(buf, symbolic_buffer)

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

def gather_taint(prog, params, trace, target):
    print "Gathering taint..."
    m = Manticore(prog, params)

    m.context['target_fd'] = -1
    m.context['target_file'] = 'homeland.txt'

    syscall_lookup = {
        SYS_READ: handle_read,
        SYS_OPEN: handle_open,
        SYS_CLOSE: handle_close
    }

    @m.hook(target)
    def save_taint(state):
        print state.cpu
        m.terminate()

    @m.hook(None)
    def follow_trace(state):
        if not state.cpu.PC <= trace:
            state.abandon()

        cpu = state.cpu
        insn = cpu.instruction
        insn_name = insn.insn_name()

        if insn_name == 'syscall':
            # rdi, rsi, rdx, r10, r8, r9
            if cpu.RAX in syscall_lookup:
                syscall_lookup[cpu.RAX](m, state)

    m.run()

def main():
    prog = 'a.out'
    params = []

    # gather_trace(prog, params)
    with open('trace.txt', 'r') as f:
        c = f.read()
    trace = set([int(ea) for ea in c.split('\n')[:-1]])
    target = 0x4006f9

    gather_taint(prog, params, trace, target)

main()