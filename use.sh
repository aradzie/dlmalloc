#!/usr/bin/env bash

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    env LD_PRELOAD=./cmake-build-debug/libdlalloc.so $*
elif [[ "$OSTYPE" == "darwin"* ]]; then
    env DYLD_INSERT_LIBRARIES=./cmake-build-debug/libdlalloc.dylib $*
else
    echo Unsupported OS type
fi
