VMFuzz (developper documentation)
=====================================


**All documentations**
-----------------------
- [Installation Guide](Install.md)
- [Minimal usage](Usage.md)
- [Configuration Guide](Configuration.md)
- [How to create an autoit script](autoit_lib/)
- [Fuzzers available](fuzzers/README.md)
- [Particular behaviors details](Behavior.md)
- [Exploitatbility analysis](exploitability/) (to be dev)
- [Database communication](Database.md) (to be dev)
- [Modules tests](tests/README.md) 

**
Tested on Win 7, fuzzing with radamsa.

Programs tested:
- Sumatra pdf (v.3.2.1): http://www.sumatrapdfreader.org/download-free-pdf-viewer.html
- Easy RM to MP3 convertor (v2.3.7, with buffer overflow from: https://www.exploit-db.com/exploits/9177/)
- Vlc (v2.2.1, with buffer overflow from: https://www.exploit-db.com/exploits/38485/): https://www.videolan.org/vlc/releases/2.2.1.html
- WinSCP 
- 7zip


**Limitations**
----------------

- Architecture only works with "radamsa-like" fuzzers and winafl;
- Only fuzz one file;
- Need to be careful when writting autoit script.

