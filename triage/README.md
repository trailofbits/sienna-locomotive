# Crash Triage

## Pin

Copy the `pin/taint` directory to your `/path/to/pin-version/source/tools/`. 

Clone [RapidJSON](https://github.com/miloyip/rapidjson) and copy `include/rapidjson` to your `/path/to/pin-version/source/tools/`. 

Compile with `make`.

Running looks something like:

```
./pin -t source/tools/taint/obj-intel64/taint.so -f /tmp/crash_scratch -d -o out.txt -- /path/to/sienna-locomotive/triage/corpus/asm/crashy_mccrashface 13
```