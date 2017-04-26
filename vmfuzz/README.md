VMFuzz (developer documentation)
=====================================

The vmfuzz documentation is only for developer purpose.

The vmfuzz documentation is built as follow:

```shell
cd docs
make html
```

**All documentations**
-----------------------
- [Configuration Guide](Configuration.md)
- [Fuzzers available](fuzzers/README.md)
- [Particular behaviors details](Behavior.md)
- [Exploitatbility analysis](exploitability/) 
- [Database communication](Database.md) 


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

