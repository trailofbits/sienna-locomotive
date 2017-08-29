import subprocess
import yaml
import json
import sys
import re
import os

inputs = {
    'Space_Attackers': 'magic\n' + ('\n\n\n\nd\n' * 24) + ('\n' * 16) + ((('w\n' * 10) + 's\n') * (280)) + 's\n' + 'd\n' + 'q\n',
    'Fortress': "\x10\x87\x04\x08\n-1337\n0\n2\n1\n0\n1\n0\n6\n0\nThis is a great program Love it! Thanks for making this :) G\x24\x35\x06\x08I am done with this-\n6\n1\nHELO\n",
    'electronictrading': "\x03" + "\x00" * 3 + "A" * 4 + "\x00" * 12 + "\x05" + "\x00" * 19,
    # 'UTF-late': '\x01\x00\x00\x00\x2e\x2e\xc0\xaf\x61\x64\x6d\x69\x6e\xc0\xaf\x41\x41\x41\x41\x00\x04\x00\x00\x00\x42\x42\x42\x42\xff\xff\xff\xff',
    'cotton_swab_arithmetic': '\x26\x00\x02\xff\xff\x10\x00\x22\xff\xff\x01\x00\x07\x00\x00\x05\x00\x00\x48\x22\xff\xff\x00\x00\x0f\x00\x00\x08\x20\x00\x00\x05\x00\x07\x00\x00\x00\x00\xaa\xaa',
    'String_Storage_and_Retrieval': '\x61\x2f\x01\x80\x61\x61\x61\x61\x61\x61\x61\x61\x0a\x61\x2f\xfa\x67\x61\x61\x61\x61\x61\x61\x61\x61\x0a\x64\x2f\xfa\x67\x61\x61\x61\x61\x61\x61\x61\x61\x0a\x78\x0a',
    'middleout': "\x64\x65\x63\x6f\x6d\x70\x72\x65\x73\x73\x0a" + "\x61" * 95 + "\x8f\xff\x00\x08" * 24 + "\xed\xac\xed\xde\x0a" + "\x71\x75\x69\x74\x0a",
    'pizza_ordering_system': "pizzapass\n" + "1\npov\n" + "1\n1\n5\n3\n1\n2\n4\n1\n1\n5\n2\n7\n" + "quit\n",
    # 'SOLFEDGE': "\x0b\x47\x0c\x00" + "\x00\x08\x00\x00" + "DFABGCFFGGBDEDDGGAEDDDABEDFFEFAFEDCEDBEFFGFCADAFBDACAEBBFAAGAEEBACFAAEBBGGABFBDEEBFCGFBDDFBCDDFDDBFGEGFEBDGBCBBBBEEAGAABEBDCECBEBADEFBADBECBADFGGEBFCCFCCEADDAECCEEFADDBGEGDFFDAFGCGFAFBBDBGFCFBBCGABFEADFBCAFFBCEEBEGBFCCEEEEEDAGEDAFCFAFEDDBGGDBCBCECABCCGGACCBEFFDDFDGBFBCFGEBFDEAGGEFEAGGDCDBCDAGFFCAEAGFGCEACGEFBEFEFDEFECDDGEFCBEDDACDABFCABEBDACEDGFEEDADBCDFCDCCCBGECDEBDFGCBGABDEDFCCFBEEDGECCGGCGGBADCGCBAFEAAABBGGGGEGDBBDDDDAGFCGBBBCABGDAFDECFGBBDBDAEDAAAGCGEDEBCBCAGDGECGEFFBEDBBEDCEEFBFDEGBGFGBDABGEDDAAEDEBAGGGFEFABBCCCCFECDDEBDADEACACEEECCAGFABEBFAGBEBDEAGFBGAGGFCGFAFCBABFFAEAAAFFDFAEFGBFABEACEEACFAECCEEFGFGECBFDGAABGGCFEAGAFGGECEFDDBDBDADBGAEABGGCBCABDDFBCADEFFFFGGDGECECFFBBECCFAAGACCEEDFBDDGBFDGBAAEGGEEBDEEBDDFFCGCBCCEEDGBEEFCAEBBGBECEAFGGEDDCEGFDEGFFEECDABDCBAEBDGGDGFBBBABBAFAAAACEFDFFDEGBEGBCDCEAEAGDFBBEBFADBAFBGFGEFAAFFGEAEFGFGEEAEDFBDCDAGDFCGAGEFAAGGGFBBDDGABEDCEAFAEBFGFAFFAEBCDABFEDCDFFEBCGFGGDGFABGFCAFAADBEAECGBEADFCEDFAEFAFGEFFGCBGBECCGCEDGCFCDFEGABFFGGFCBGGEEEFGDEEEBFBCCGEDEFAFGDGDBAEBADACDDCDEDBBEBAEGECEGEBFAGDGEGCFDCDGADADFFAGAGGABAGBBFGGDGDADBEBBBCGEBBGCAEBBECFDACGGDDBFFFCAAAFEDDACEEDBADBDAACCBADGBDFEFBBEDBBFAGGEDDBEEDFCBDEEBFEBBAGAGCFGEDACBAEAEFFEEDGAEAGGBDGGFFFCBAGDDDAEGGDAAEBFEBGCADFFAFACCDFBADBEAFDFEBCDFCFGABGCEFFBEBEGCEABCFDFAFFBCFFBFEEADBFEFGADEFFGCEBFACEDADGBAEAAEGEFEAEEEFCCGCBAFEACCCDDBADAFEDDADGBCDAGCGDCDCAAFCGAFGEEDFDEDEBAAFGDEEBCEFFCAEAAEDBDEBCBFDEBEEDEDFFDGCCFDCECDFCGDBBCDFBFFFCFEEBAGEAFFCAFBGGFDFBCGEEACDAFABDFDFADGGDCFCBACGBBCAFECCDBEGCDDGBGDBFDGAAFEFBBGCAEECBFBCAADDBEFABFCCBFFDDFBDBBGFDAFDDCAGEFEADDFBBGCCGBBACCDFBDEEBAEBGCBDEBGBDDBECACCEGBCGAGCDAFDEEBBCAFDDCFDCCAGEECBFADDEFEDDDDDGBFEGFDFCDECEFGDECDCBACBEEBGGDGBGDBBDEAFBBFCBBAADEFCFDDBCGAABGCFBCBEAAEBBFACDFCAEGGDAFCCEEAEAFCCDEEFCDBGDAGEBEGBDBFEEBCCBABDCEGECFGGEFEAAGAGDAFEEFADEDBCGAEBGFDBBDAFFDDDBEACFGDGFBGEDCECGDADAECDCGBFAEGFDEBGGFFCFEECDBEECDDBAFBDBDCDFDAFGEADDFGEACCGBEEEBAACEEAEFGBDGFBADEBAEEGFCBGCBDFFECGFDCBFAGDCGADDEAFFGEAGCECDCEBCBEAGEEGAGCFFCCGGCBGDGFEBBFCEBGEFGABBBCBEBCCDEFAABBEEFDEFAEDCDADBFCEACFBCDBCBCCAEABEGFGCCAGEGEFBDGGCCEEBFE",
}

def init():
    '''
    Validates and initializes paths.
    '''

    global config
    with open('../config.yaml') as f:
        config = f.read()

    config = yaml.load(config)

    tool_path = os.path.join(config['tool_dir'], 'obj-ia32', 'taint.so')
    if not os.path.exists(tool_path):
        print 'ERROR: cannot find taint.so at %s' % tool_path
        sys.exit(1)
    config['tool_path'] = tool_path

    pin_path = os.path.join(config['pin_dir'], 'pin')
    if not os.path.exists(pin_path):
        print 'ERROR: cannot find pin at %s' % pin_path
        sys.exit(1)
    config['pin_path'] = pin_path

    if not os.path.exists(config['cb_dir']):
        print 'ERROR: cannot find cb-multios at %s' % config['cb_dir']
        sys.exit(1)

def get_path(cb):
    return os.path.join(config['cb_dir'], 'processed-challenges', cb, 'bin', cb)

def get_tests(tests):
    checked = []
    for cb in tests:
        cb_path = get_path(cb)
        if os.path.exists(cb_path):
            checked.append(cb)

    return checked

def extract_results(out):
    pattern = '#### BEGIN CRASH DATA JSON\n.*?#### END CRASH DATA JSON'
    matches = re.findall(pattern, out, re.DOTALL)

    if len(matches) == 0:
        print 'FAIL'
        print 'ERROR: no json found'
        sys.exit(1)

    if len(matches) > 1:
        print 'FAIL'
        print 'ERROR: multiple json found'
        sys.exit(1)        

    result_str = matches[0]
    results = '\n'.join(result_str.split('\n')[1:-1])
    # results = json.loads('\n'.join(result_str.split('\n')[1:-1]))

    return results

def run_tests(tests):
    for cb in tests:
        print cb,
        
        cb_path = get_path(cb)
        cmd = [config['pin_path'], '-t', config['tool_path'], '--', cb_path]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        
        stdout, _ = proc.communicate(inputs[cb])
        out = extract_results(stdout)
        
        with open('data/' + cb + '._json', 'w') as f:
            f.write(out)
        
        print 'OK'

def output_inputs():
    for cb in inputs:
        with open('/tmp/%s_input' % cb, 'w') as f:
            f.write(inputs[cb])

def main():
    tests = []
    if len(sys.argv) > 1:
        tests = [ea for ea in sys.argv[1:] if ea in inputs] 
    else:
        tests = inputs.keys()

    init()
    tests = get_tests(tests)

    run_tests(tests)

if __name__ == '__main__':
    # main()
    output_inputs()