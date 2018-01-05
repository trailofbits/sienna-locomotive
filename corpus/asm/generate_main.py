from datetime import datetime

template = '''
global main
main:
;   args:
;       rdi, argc
;       rsi, argv
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rcx, rdi
    mov     rax, rsi
    call    parse_args
%s    xor     rax, rax
    call    show_usage
main_finish:
    mov     rax, 2
    call    exit
%s
'''

usage_template = '''
    use_err     db 'USAGE: ./test TEST_NUMBER',0x0a
%s    use_len     equ $-use_err
'''


def generate_code(original):
    tests = original.split(';   TESTS   ;')[1].split(';   UTILITY FUNCTIONS   ;')[0].split('\n')
    names = [ea.split(' ')[1] for ea in tests if ea.startswith('global')]

    count = 0
    jmps = ''
    branches = ''
    usage = ''
    for name in names:
        usage += "                db '%d\t%s',0x0a\n" % (count, name)

        jmps += '    cmp     rax, %d\n' % count
        jmps += '    je      test_%s\n' % name
        count += 1

        branches += 'test_%s:\n' % name
        branches += '    call    %s\n' % name
        branches += '    jmp     main_finish\n'

    return usage, jmps, branches


def replace_usage(original, usage):
    use_err = usage_template % usage
    lines = original.split('\n')
    start = lines.index('    ; GEN USAGE')
    end = lines.index('    ; END USAGE')
    return '\n'.join(lines[:start+1] + [use_err.strip('\n')] + lines[end:])

def replace_main(modified, jmps, branches):
    main = template % (jmps, branches)
    lines = modified.split('\n')
    start = lines.index('; GEN MAIN')
    end = lines.index('; END MAIN')
    return '\n'.join(lines[:start+1] + [main.strip('\n')] + lines[end:])

def main():
    with open('crash.asm') as  f:
        original = f.read()

    usage, jmps, branches = generate_code(original)

    modified = replace_usage(original, usage)
    modified = replace_main(modified, jmps, branches)

    backup = '/tmp/crash.asm_%s' % str(datetime.now()).replace(' ', '_')
    with open(backup, 'w') as  f:
        f.write(original)

    print 'Backup written to %s' % backup

    with open('crash.asm', 'w') as f:
        f.write(modified)

if __name__ == '__main__':
    main()