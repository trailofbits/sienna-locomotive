import unittest
#from test import support
import test.support as support
import sys
import subprocess
import shlex

class Test1(unittest.TestCase):
    
    def test_main(self):
        
        cmd =  [ r'.\dynamorio\bin64\drrun.exe',
            r'-c',
            r'build\wizard\Debug\wizard.dll',
            r'--',
            r'build\corpus\test_application\Debug\test_application.exe',
            r'0' ]
        
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,  stderr=subprocess.PIPE, close_fds=False)
        stdout, stderr = p.communicate()
        stderr = str(stderr)
        self.assertRegexpMatches( stderr, r'.*aa8b10f2e5498367555fe6f09175f4d89f93cfe4d4af736cc5245cb8ac7ba1e9.*' )


def main():
    support.run_unittest(Test1)


if __name__ == '__main__':
    #unittest.main()
    main()