# Sienna Locomotive 2

The purpose of this repository is to make a system that enables continous integration for fuzzing. 

## Directory Structure

In the repository targeted for fuzzing, you must create a .fuzzci folder. When building, it can be assumed that libFuzzer.a will be in the .fuzzci directory and the build process will be starting from the root of the repository (exception is this repo during testing, which starts in the `sample/` directory). This folder structure is as follows:

```bash
.fuzzci/
    target_name/
        config.yml
        entry.cc
        corpus/
```

### target_name

The target name will act as the unique identifier for that fuzz target. It should start with `target_` (not currently enforced anywhere).

### config.yml

This is the configuration file. Required fields are `build` (the command(s) that build the fuzzable executable), `executable` (the path to the executable produced by `build`), and `corpus` (the directory for the seed files and future crashes). Additionally, you may use `options`, which acts as a set of additional options to be passed when the fuzzable is run.

```yaml
# command that builds the fuzzable
build:
  - mkdir -p build
  - cd build
  - cmake ..
  - make fuzz_target_parse

# path to the fuzzable
executable:
  build/.fuzzci/target_parse/fuzz_target_parse

# corpus that should be used
# also used as the artifact_prefix unless overridden in options
corpus:
  .fuzzci/target_parse/corpus/

# additional options taken by libFuzzer
options:
  '-close_fd_mask': 3
```

### entry.cc

This is your libFuzzer entry point for this target. It should define the `LLVMFuzzerTestOneInput` function.

```c++
#include "../../src/main/parse.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Parser parser;
    parser.parse(data, size);
    return 0;
}
```

### corpus/

This is the directory where you place your seed files. It will also be used to store crashes (for retest purposes) unless otherwise specified with `-artifact_prefix` under `options` in `config.yml`.

## Binaries

I think binaries should be handled outside of git. Keep their .fuzzci entry the same, with entry points, configs / build commands, and corpora. Instead of them sitting in the git repo, allow users to upload them. This will allow them to add version info and other meta information. 

These binaries need to be ran through the `disass`, `lift`, `opt` process. This may take 30 minutes to 1 hour to produce a binary. This should be a 1 time process for each binary though, store the bit code and avoid doing it again. Provide the download of the bitcode so that users can create good build instructions. (Is the process upload, wait, download, build too cumbersome? We could instead simply compile it back with instrumentation and treat it as a normal library, avoiding the user having to get it back. Best choice is probably to do both, allow the users to provide a build command for a library or a build command for bitcode, specify which with a config option.)

Provide the option to users to do the lifting themselves and upload bitcode, incase they want to make certain custom modifications.

Error reporting needs to be top tier. If remill fails we should know about it. Automatically open a ticket and send it to the user?

Email notifications for when remill completes. I've used [Sparkpost](https://www.sparkpost.com/) before, we'll definitely fit within the free tier.

Figure out if libfuzzer can disregard or move on after finding certain crashes. An early crash early in a code base could potentially block further fuzzing.

## Web Server

Web server is prototyped in Flask. To run:

```bash
export FLASK_APP=web.py
python -m flask run
```

Current endpoints:

### /retest/[target]

If visited without optional `[target]`, this will rerun all fuzz targets in the `.fuzzci` folder. If the optional `[target]` is provided, it will run only that target. 