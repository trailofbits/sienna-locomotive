import json
import subprocess

template = '''
main PROC
; main function
  prologue
  mcall   parse_args
%s  mcall   show_usage
main_finish:
  mov     rcx, 0
  mcall   ExitProcess
%smain ENDP 
'''

usage_template = '''
  use_err     db "USAGE: ./crashes.exe TEST_NUMBER",0Ah
%s  use_len     equ $-use_err
'''

def generate_code(original):
    tests = original.split(';   TESTS   ;')[1].split(';  UTILITY  ;')[0].split('\n')
    names = [ea.split(' ')[0] for ea in tests if 'PROC' in ea]

    count = 0
    jmps = ''
    branches = ''
    usage = ''
    for name in names:
        usage += "              db '%d\t%s',0Ah\n" % (count, name)

        jmps += '  cmp     rax, %d\n' % count
        jmps += '  je      test_%s\n' % name
        count += 1

        branches += 'test_%s:\n' % name
        branches += '  mcall   %s\n' % name
        branches += '  jmp     main_finish\n'

    return usage, jmps, branches


def replace_usage(original, usage):
    use_err = usage_template % usage
    lines = original.split('\n')
    start = lines.index('  ; GEN USAGE')
    end = lines.index('  ; END USAGE')
    return '\n'.join(lines[:start+1] + [use_err.strip('\n')] + lines[end:])

def replace_main(modified, jmps, branches):
    main = template % (jmps, branches)
    lines = modified.split('\n')
    start = lines.index('; GEN MAIN')
    end = lines.index('; END MAIN')
    return '\n'.join(lines[:start+1] + [main.strip('\n')] + lines[end:])

def main():
    with open('crashes.asm') as  f:
        original = f.read()

    usage, jmps, branches = generate_code(original)

    modified = replace_usage(original, usage)
    modified = replace_main(modified, jmps, branches)

    backup = 'bak_crashes.asm' #_%s' % str(datetime.now()).replace(' ', '_')
    with open(backup, 'w') as  f:
        f.write(original)

    print('Backup written to %s' % backup)

    with open('crashes.asm', 'w') as f:
        f.write(modified)

    with open('config.json') as f:
        config = json.loads(f.read())

    proc = subprocess.Popen([
        config['ml64'], "crashes.asm", "/link", 
        "/subsystem:console", "/libpath:" + config['lib'],
        "/defaultlib:kernel32.lib", "/entry:main"])

    proc.wait()

if __name__ == '__main__':
    main()