import unittest
#from test import support
import test.support as support
import sys
import subprocess
import shlex


def runAndCaptureOutput( cmd ):
    if type(cmd) == type([]):
        cmd = " ".join(cmd)

    return subprocess.getoutput(cmd)
    # p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,  stderr=subprocess.PIPE, close_fds=True)
    # stdout, stderr = p.communicate()
    # stdout = str(stdout)
    # stderr = str(stderr)
    # return stdout, stderr

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


def main():
    support.run_unittest(TestWizard)


if __name__ == '__main__':
    #unittest.main()
    print("Make sure to  .\make reconfig  first.")
    main()