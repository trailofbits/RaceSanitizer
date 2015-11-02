#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))
F=$(realpath $1)

export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=$DIR/third_party/llvm/build/bin/

# Instrument the test case.
$DIR/third_party/whole-program-llvm/extract-bc $F
$DIR/third_party/llvm/build/bin/opt -load $DIR/bin/libRaceSanitizer.so -rsan $F.bc -o $F.inst.bc
$DIR/third_party/llvm/build/bin/llvm-link $DIR/bin/Runtime.bc $F.inst.bc -o $F.linked.bc
$DIR/third_party/llvm/build/bin/opt -O2 $F.linked.bc -o $F.rsan.bc
$DIR/third_party/llvm/build/bin/opt -O2 $F.bc -o $F.orig.bc
$DIR/third_party/llvm/build/bin/clang++ -O2 -o $F.rsan $F.rsan.bc $LDFLAGS -lpthread -ldl
$DIR/third_party/llvm/build/bin/clang++ -O2 -o $F.orig $F.orig.bc $LDFLAGS -lpthread -ldl



