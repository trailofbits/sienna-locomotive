import unittest
#from test import support
import test.support as support
import sys
import subprocess
import shlex
import glob
import os

def runAndCaptureOutput( cmd ):
    if type(cmd) == type([]):
        cmd = " ".join(cmd)
    out =  subprocess.getoutput(cmd)
    #print('cmd', cmd)
    return out

class TestWizard(unittest.TestCase):

    def test_0(self):
        
        cmd =  [ r'.\dynamorio\bin64\drrun.exe',
            r'-c',
            r'build\wizard\Debug\wizard.dll',
            r'--',
            r'build\corpus\test_application\Debug\test_application.exe',
            r'0' ]
        
        output = runAndCaptureOutput(cmd)
        self.assertTrue(  r'buffer":[65,65,65,65,65,65,65,65]'  in output )

    def test_2(self):
        
        cmd =  [ r'.\dynamorio\bin64\drrun.exe',
            r'-c',
            r'build\wizard\Debug\wizard.dll',
            r'--',
            r'build\corpus\test_application\Debug\test_application.exe',
            r'2' ]
        
        output = runAndCaptureOutput(cmd)
        self.assertTrue(  r'[60,104,116,109,108,62,10,32]' in output )

    def test_RegQueryValueEx(self):
        cmd = r'echo 0 | python .\harness.py -r3 -l -v -t build\\corpus\\test_application\\Debug\\test_application.exe -a 4 -f'
        output = runAndCaptureOutput(cmd)
        self.assertTrue( 'Process completed after' in output )


    def test_captureStdout(self):

        targetString = 'XXXWWWXXX'
        # First version have -l, inlining stdout for us to capture.   String "XXXWWWXXX" should appear
        cmd = r'echo 0 | python .\harness.py -r3 -l -v -t build\\corpus\\test_application\\Debug\\test_application.exe -a 9 -f'
        output = runAndCaptureOutput(cmd)
        self.assertTrue( targetString in output )


        # This version does not have have -l, so we aren't capturing stdout and String "XXXWWWXXX" should NOT appear
        cmd = r'echo 0 | python .\harness.py -r3 -v -t build\\corpus\\test_application\\Debug\\test_application.exe -a 9 -f'
        output = runAndCaptureOutput(cmd)
        self.assertFalse( targetString in output )



    def test_TheWiz(self):
        cmd = r'echo 0 | python .\harness.py -v'
        output = runAndCaptureOutput(cmd)
        self.assertTrue( 'Process completed after' in output )

    def test_quickCrash(self):
        cmd =  r'echo 0 | python .\harness.py -c -x -l -v -t build\corpus\test_application\Debug\test_application.exe -a 10 -f'
        output = runAndCaptureOutput(cmd)
        self.assertTrue( 'Process completed after' in output )
        self.assertRegex(  output, r'Triage .*: breakpoint .*caused EXCEPTION_BREAKPOINT'  )
        self.assertTrue( 'int3' in output )

class  TestMinidumpOnly(unittest.TestCase):
    def test_minidump(self):
        minidumpsdir = "breakpad/src/processor/testdata"
        pattern = "%s/*.dmp" % minidumpsdir
        i = 0
        paths = [ _ for _ in glob.glob(  pattern ) ]
        paths = " ".join(paths)
        cmd = r'build\triage\Debug\triager.exe ' + paths
        print("cmd", cmd)
        
        out = runAndCaptureOutput(cmd)
        print(out)


class  TestTriage(unittest.TestCase):
    def test_triage(self):
        workingdir = os.path.join( os.environ['APPDATA'],  "Trail of Bits", "fuzzkit", "runs" )        
        pattern = "%s/*/*.dmp" % workingdir
        print("pattern", pattern)
        for path in glob.glob(  pattern ):
            #paths = " ".join(paths)
            cmd = r'build\triage\Debug\triager.exe "%s"' % path
            print("cmd", cmd)        
            out = runAndCaptureOutput(cmd)
            print(out)


def main():
    
    if len(sys.argv)==1:
        clazz = TestWizard
    else:
        clazz = getattr(sys.modules[__name__], sys.argv[1] )

    print("clazz", clazz)
    support.run_unittest(clazz)


if __name__ == '__main__':
    print("Make sure to  .\make reconfig  first.")
    print("You can also pass a specific test class to run on the command line like  regress.py TestMinidump")
    main()
