#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

sudo apt-get update
sudo apt-get install -y binutils-dev build-essential git cmake

# Directory in which this script resides (i.e. RaceSanitizer root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

# Versions of things.
LLVM_VERSION=3.7.0

mkdir -p $DIR/third_party

# Download whole-program-llvm
cd $DIR/third_party
git clone git@github.com:travitch/whole-program-llvm.git

# Download LLVM.
wget http://llvm.org/releases/3.7.0/llvm-${LLVM_VERSION}.src.tar.xz
tar xf llvm-$LLVM_VERSION.src.tar.xz
rm llvm-$LLVM_VERSION.src.tar.xz

# Download Clang.
wget http://llvm.org/releases/3.7.0/cfe-${LLVM_VERSION}.src.tar.xz
tar xf cfe-${LLVM_VERSION}.src.tar.xz
rm cfe-${LLVM_VERSION}.src.tar.xz

# Move things around.
mv llvm-$LLVM_VERSION.src $DIR/third_party/llvm
mv cfe-${LLVM_VERSION}.src $DIR/third_party/llvm/tools/clang

# Compile LLVM & Clang.
mkdir $DIR/third_party/llvm/build
cd $DIR/third_party/llvm/build

CFLAGS="-g3" CXXFLAGS="-g3" LDFLAGS="-g" \
cmake ../ \
    -DCMAKE_BUILD_TYPE:STRING=Debug \
    -DLLVM_ENABLE_RTTI:BOOL=ON \
    -DLLVM_TARGETS_TO_BUILD:STRING="X86" \
    -DLLVM_ENABLE_ASSERTIONS:BOOL=ON \
    -DLLVM_ENABLE_THREADS:BOOL=ON
make

mkdir -p $DIR/bin

# Compile the plugin.
cd $DIR/bin
cmake -DRSAN_DIR=$DIR $DIR/lib/Instrumentation
make

# Compile the test case.
$DIR/third_party/llvm/build/bin/clang++ -O2 -gline-tables-only -std=c++11 -emit-llvm -c $DIR/Test.cc -o $DIR/bin/Test.bc

# Compile the runtime.
$DIR/third_party/llvm/build/bin/clang++ -O3 -gline-tables-only -std=c++11 -emit-llvm -c $DIR/lib/Runtime/Runtime.cpp -o $DIR/bin/Runtime.bc

# Link and compile the test case.
$DIR/third_party/llvm/build/bin/clang++ -std=c++11 -Oz -gline-tables-only $DIR/bin/Test.bc $DIR/bin/Runtime.bc -o $DIR/bin/Test -lpthread -ldl

