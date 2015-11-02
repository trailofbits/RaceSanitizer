#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=$DIR/third_party/llvm/build/bin/
export CC=$DIR/third_party/whole-program-llvm/wllvm
export CXX=$DIR/third_party/whole-program-llvm/wllvm++
export LLVM_LINK=$DIR/third_party/llvm/build/bin/llvm-link
#export CFLAGS="-gline-tables-only"
#export CXXFLAGS="-gline-tables-only"
#export LDFLAGS="-gline-tables-only"
eval "$@"
