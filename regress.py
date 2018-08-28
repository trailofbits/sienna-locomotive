import unittest
import test.support as support
import sys
import subprocess
import shlex
import glob
import os
import codecs

DEBUG=False

TEST_APPLICATION='build/corpus/test_application/Debug/test_application.exe'
TRIAGER=r'build\triage\Debug\triager.exe'


def runAndCaptureOutput( cmd ):

    if type(cmd) == type([]):
        cmd = " ".join(cmd)

    if DEBUG:
        print( '\n[%s]' % cmd)
    # Modify the next line at your own risk. There are subtle char encoding issues than can arise.  We did pass `text=True` early but this
    # is only supported in >= Python 3.7
    out = subprocess.run( cmd, universal_newlines=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, encoding='iso8859' )
    out = out.stdout + out.stderr

    if DEBUG:
        print( "\n<%s>" % out )
    return str(out)

class TestWizard(unittest.TestCase):

    def test_0(self):

        cmd =  [ r'dynamorio\bin64\drrun.exe',
            r'-c',
            r'build/wizard/Debug/wizard.dll',
            r'--',
            TEST_APPLICATION,
            r'0' ]

        out = runAndCaptureOutput(cmd)
        self.assertTrue(  r'buffer":[65,65,65,65,65,65,65,65]'  in out )

    def test_2(self):

        cmd =  [ r'dynamorio\bin64\drrun.exe',
            r'-c',
            r'build/wizard/Debug/wizard.dll',
            r'--',
            TEST_APPLICATION,
            r'2' ]

        out = runAndCaptureOutput(cmd)
        self.assertTrue(  r'[60,104,116,109,108,62,10,32]' in out )

    def test_registry(self):
        cmd = r'echo 0 | python harness.py -g -r3 -l -v -e WIZARD -t '+ TEST_APPLICATION +' -a 4 -f'
        out = runAndCaptureOutput(cmd)
        self.assertTrue( '0) RegQueryValueEx' in out )
        self.assertTrue( 'Process completed after' in out )
        cmd = r'echo 0 | python harness.py -r3 -l -v -e WIZARD -t '+ TEST_APPLICATION +' -a 4 -f'
        out = runAndCaptureOutput(cmd)
        self.assertFalse( '0) RegQueryValueEx' in out )
        self.assertTrue( 'Process completed after' in out )


    def test_captureStdout(self):

        targetString = 'XXXWWWXXX'
        # First version have -l, inlining stdout for us to capture.   String "XXXWWWXXX" should appear
        cmd = r'echo 0 | python harness.py -r3 -l -v -t '+ TEST_APPLICATION +' -a 9 -f'
        out = runAndCaptureOutput(cmd)
        self.assertTrue( targetString in out )


        # This version does not have have -l, so we aren't capturing stdout and String "XXXWWWXXX" should NOT appear
        cmd = r'echo 0 | python harness.py -r3 -v -t '+ TEST_APPLICATION +' -a 9 -f'
        out = runAndCaptureOutput(cmd)
        self.assertFalse( targetString in out )

    def test_TheWiz(self):
        cmd = r'echo 0 | python harness.py -v'
        out = runAndCaptureOutput(cmd)
        self.assertTrue( 'Process completed after' in out )



    def test_quickCrash(self):
        cmd =  r'echo 0 | python harness.py -c -x -l -v -t '+ TEST_APPLICATION +' -a 10 -f'
        out = runAndCaptureOutput(cmd)
        self.assertTrue( 'Process completed after' in out )
        #self.assertRegex(  out, r'Triage .*: breakpoint .*caused EXCEPTION_BREAKPOINT'  )
        self.assertTrue(  'Crashash' in out )
        self.assertTrue( ' None/EXCEPTION_BREAKPOINT' in out )

        workingdir = os.path.join( os.environ['APPDATA'],  "Trail of Bits", "fuzzkit", "runs" )
        pattern = "%s/*/*.dmp" % workingdir
        paths = glob.glob(  pattern )
        self.assertTrue( len(paths) > 0 )

        # with open(paths[0]) as f:
        #     data = f.read()
        #     self.assertTrue( "instructionPointer" in data )


    def test_triage(self):
        for _ in range(3):
            cmd =  r'echo 0 | python harness.py -c -x -l -v -t '+ TEST_APPLICATION +' -a 10 -f'
            out = runAndCaptureOutput(cmd)

        workingdir = os.path.join( os.environ['APPDATA'],  "Trail of Bits", "fuzzkit", "runs" )
        pattern = "%s/*/initial.dmp" % workingdir
        for path in glob.glob(  pattern ):
            #paths = " ".join(paths)
            cmd = '%s "%s"'% ( TRIAGER, path )
            out = runAndCaptureOutput(cmd)
            for _ in [ 'Crashash', 'Exploitability', 'Ranks', 'Crash Reason' ]:
                self.assertTrue(  _ in out )

    def test_fuzzgoat(self):
        cmd = r'echo 0 | python harness.py -e WIZARD -v -l  -t ./build/fuzzgoat/Debug/fuzzgoat.exe -a ./fuzzgoat/input-files/validObject'
        out = runAndCaptureOutput(cmd)
        self.assertRegex( out, r'0[)] ReadFile from.*validObject' )


def main():

    global DEBUG
    if len(sys.argv)==1:
        clazz = TestWizard
    else:
        DEBUG=True
        clazz = getattr(sys.modules[__name__], sys.argv[1] )

    print("clazz", clazz)
    support.run_unittest(clazz)


if __name__ == '__main__':
    print("Make sure to  ./make reconfig  first.")
    print("You can also pass a specific test class to run on the command line like  regress.py TestMinidump")
    main()
