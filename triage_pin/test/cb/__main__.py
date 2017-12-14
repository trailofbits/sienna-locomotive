from .. import shared
import subprocess
import timeit
import yaml
import json
import sys
import os

inputs = {
    'Space_Attackers': 'magic\n' + ('\n\n\n\nd\n' * 24) + ('\n' * 16) + ((('w\n' * 10) + 's\n') * (280)) + 's\n' + 'd\n' + 'q\n',
    'Fortress': "\x10\x87\x04\x08\n-1337\n0\n2\n1\n0\n1\n0\n6\n0\nThis is a great program Love it! Thanks for making this :) G\x24\x35\x06\x08I am done with this-\n6\n1\nHELO\n",
    'electronictrading': "\x03" + "\x00" * 3 + "A" * 4 + "\x00" * 12 + "\x05" + "\x00" * 19,
    'UTF-late': '\x01\x00\x00\x00\x2e\x2e\xc0\xaf\x61\x64\x6d\x69\x6e\xc0\xaf\x41\x41\x41\x41\x00\x04\x00\x00\x00\x42\x42\x42\x42\xff\xff\xff\xff',
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

    shared.init(32)

    if not os.path.exists(shared.config['path_cb']):
        print 'ERROR: cannot find cb-multios at %s' % shared.config['path_cb']
        sys.exit(1)

    data_path = os.path.join(shared.config['path_sienna'], 'triage/test/cb/data/')
    shared.config['data_path'] = data_path

def get_path(cb):
    return os.path.join(shared.config['path_cb'], 'processed-challenges', cb, 'bin', cb)

def get_tests(tests):
    checked = []
    for cb in tests:
        cb_path = get_path(cb)
        if os.path.exists(cb_path):
            checked.append(cb)

    return checked

def run_tests(tests):
    results = {}

    for test in tests:
        print test,
        
        cb_path = get_path(test)
        cmd = [shared.config['pin_path'], '-t', shared.config['tool_path'], '--', cb_path]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        
        stdout, _ = proc.communicate(inputs[test])
        data = shared.extract_results(stdout)

        expected_path = os.path.join(shared.config['data_path'], '%s.json' % test)
        with open(expected_path) as f:
            expected_contents = f.read()
        expected = json.loads(expected_contents)
        
        if data['score'] != expected['score']:
            print 'FAIL'
            results[test] = False
            continue

        if data['signal'] != expected['signal']:
            print 'FAIL'
            results[test] = False
            continue

        if not shared.regs_match(expected, data):
            print 'FAIL'
            results[test] = False
            continue

        print 'OK'
        results[test] = True

    print results

def baseline(tests):
    total = 0
    for test in tests:
        print test,
        
        cb_path = get_path(test)
        cmd = [cb_path]
        start = timeit.default_timer()
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, _ = proc.communicate(inputs[test])
        end = timeit.default_timer()
        total += end - start
    print
    print total

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
    #baseline(tests)

if __name__ == '__main__':
    main()