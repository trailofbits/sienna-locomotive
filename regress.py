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
    
    
    # def test_noargs(self):
    #     cmd =  [ r'python.exe',
    #         r'harness.py' ]
        
    #     stdout, stderr = runAndCaptureOutput(cmd)
    #     self.assertTrue( 'caused EXCEPTION_ACCESS_VIOLATION'  in stdout )
    #     self.assertRegex(  stdout,  r"0x[a-f0-9]+: mov.*%rax.*-> %edx" )


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
        cmd = r'echo 0 | python .\harness.py -r3 -v -t build\\corpus\\test_application\\Debug\\test_application.exe -a 4 -f'
        output = runAndCaptureOutput(cmd)
        self.assertTrue( 'Process completed after' in output )


def main():
    support.run_unittest(TestWizard)


if __name__ == '__main__':
    #unittest.main()
    main()