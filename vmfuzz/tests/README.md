**Tests / Examples**
----------------

- ```context.py``` follows the advice from the Hitchhkier guide to import the modules (http://docs.python-guide.org/en/latest/writing/structure/) 
- ```test_easy.py```, ```test_sumatra.py```, ```test_vlc.py```, ```test_WinSCP.py``` are used to test the VMfuzz system
- ```test_offset.py``` used the wingdb to retrieve the modules offsets and launch winafl on them (file to be cleaned)
- ```test_winafl.py``` is used to test one winafl run (file to be cleaned)
- ```test_automated_winafl.pyt``` is used to test the winafl exploration algorithm
