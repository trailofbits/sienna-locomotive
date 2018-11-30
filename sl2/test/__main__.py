#####################################################################################################
## @package regress
# Regression testing
import glob
import os
import subprocess
import sys
import test.support as support
import unittest

## Set to true for stdout/stderr
DEBUG = True

TEST_APPLICATION = "build/corpus/test_application/Debug/test_application.exe"
TRIAGER = r"build\triage\Debug\triager.exe"


## Wrapper for subprocess.run() which is 8bit clean
def runAndCaptureOutput(cmd):
    if type(cmd) is list:
        cmd = " ".join(cmd)

    if DEBUG:
        print("\n[{}]".format(cmd), file=sys.stderr)
    out = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        shell=False,
    )
    out = out.stdout + out.stderr

    if DEBUG:
        print("\n<{}>".format(out), file=sys.stderr)
    return out


## Main class for testing
class TestWizard(unittest.TestCase):

    ## Tests that the wizard can succesfully capture the buffer from ReadFile
    def test_0(self):
        cmd = [
            r"dynamorio\bin64\drrun.exe",
            r"-c",
            r"build/wizard/Debug/wizard.dll",
            r"--",
            TEST_APPLICATION,
            r"0",
            r"-f",
        ]

        out = runAndCaptureOutput(cmd)
        self.assertTrue(b'buffer":[65,65,65,65,65,65,65,65]' in out)

    ## Tests wizard buffer capture from WinHTTPReadData
    def test_2(self):

        cmd = [
            r"dynamorio\bin64\drrun.exe",
            r"-c",
            r"build/wizard/Debug/wizard.dll",
            r"--",
            TEST_APPLICATION,
            r"2",
            r"-f",
        ]

        out = runAndCaptureOutput(cmd)
        self.assertTrue(
            b"[60,104,116,109,108,62,10,32]" in out,
            msg="This test will fail if the computer does not have an internet connection.",
        )

    ## Tests that the wizard can capture Registry Queries
    def test_registry(self):
        cmd = r"sl2-cli -W -fn 0 -r3 -l -v -e WIZARD -t " + TEST_APPLICATION + " -a 4 -f"
        out = runAndCaptureOutput(cmd)
        self.assertFalse(b"0) RegQueryValueEx" in out)
        self.assertTrue(b"CRASH PTR" in out)

    ## Tests whether we can capture stdout from the wizard/fuzzer
    def test_captureStdout(self):
        targetString = b"XXXWWWXXX"
        # First version have -l, inlining stdout for us to capture.   String "XXXWWWXXX" should appear
        cmd = r"sl2-cli -W -fn 0 -r3 -l -v -t " + TEST_APPLICATION + " -a 9 -f"
        out = runAndCaptureOutput(cmd)
        self.assertTrue(targetString in out)
        # This version does not have have -l, so we aren't capturing stdout and String "XXXWWWXXX" should NOT appear
        cmd = r"sl2-cli -W -fn 0 -r3 -v -t " + TEST_APPLICATION + " -a 9 -f"
        out = runAndCaptureOutput(cmd)
        self.assertFalse(targetString in out)

    ## Test single-stage harness running
    def test_TheWiz(self):
        cmd = r"sl2-cli -W -v -fn 0"
        out = runAndCaptureOutput(cmd)
        self.assertTrue(b"Process completed after" in out)

    ## est case #10, that an application actually crashes and that we catch the appropriate informationT
    def test_quickCrash(self):
        cmd = r"sl2-cli -W -fn 0 -c -x -l -v -t " + TEST_APPLICATION + " -a 10 -f"
        out = runAndCaptureOutput(cmd)
        self.assertTrue(b"Process completed after" in out)
        # self.assertRegex(  out, r'Triage .*: breakpoint .*caused EXCEPTION_BREAKPOINT'  )
        self.assertTrue(b"Crashash" in out)
        self.assertTrue(b" None/EXCEPTION_BREAKPOINT" in out)

        workingdir = os.path.join(os.environ["APPDATA"], "Trail of Bits", "fuzzkit", "runs")
        pattern = "%s/*/*.dmp" % workingdir
        paths = glob.glob(pattern)
        self.assertTrue(len(paths) > 0)

        # with open(paths[0]) as f:
        #     data = f.read()
        #     self.assertTrue( "instructionPointer" in data )

    ## Test the triaging is working with crashash, exploitability, etc...
    def test_triage(self):
        cmd = r"sl2-cli -W -fn 0 -c -x -l -v -t " + TEST_APPLICATION + " -a 10 -f"
        out = runAndCaptureOutput(cmd)

        workingdir = os.path.join(os.environ["APPDATA"], "Trail of Bits", "fuzzkit", "runs")
        pattern = "%s/*/initial.dmp" % workingdir
        for path in glob.glob(pattern):
            # paths = " ".join(paths)
            cmd = '%s "%s"' % (TRIAGER, path)
            out = runAndCaptureOutput(cmd)
            for _ in ["Crashash", "Exploitability", "Ranks", "Crash Reason"]:
                self.assertTrue(_ in out)


## Runs unit tests
def main():
    global DEBUG
    if len(sys.argv) == 1:
        clazz = TestWizard
    else:
        DEBUG = True
        clazz = getattr(sys.modules[__name__], sys.argv[1])

    print("clazz", clazz)
    support.run_unittest(clazz)


if __name__ == "__main__":
    print("Make sure to  ./make reconfig  first.")
    print("You can also pass a specific test class to run on the command line like `sl2-test test_triage`")
    main()
