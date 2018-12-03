#!/usr/bin/env bash

# TODO(ww): Simplify our directory structure to make it easier
# to distinguish between the files we care about being formatted correctly
# and those we don't.

function clang-format {
    # We don't actually want to output the correctly formatted files,
    # only fail if the format is currently incorrect.
    clang-format-7 -style=file "${@}" > /dev/null
}

# SL2 server.
clang-format server/server.cpp include/server.hpp

# DR clients.
clang-format fuzzer/fuzzer.cpp wizard/wizard.cpp tracer/tracer.cpp

# Common files.
clang-format common/*.{c,cpp} include/common/*.{h,hpp}

# Harness and GUI.
flake8 sl2/**/*.py
