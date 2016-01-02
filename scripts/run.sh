#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))
F=$(realpath $1)

echo "Processing ${F}"

export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=$DIR/third_party/llvm/build/bin/

# Instrument the test case.
echo "Extracing bitcode"
$DIR/third_party/whole-program-llvm/extract-bc $F
$DIR/third_party/llvm/build/bin/opt -load $DIR/bin/libRaceSanitizer.so -rsan -O2 $F.bc -o $F.inst.bc
$DIR/third_party/llvm/build/bin/clang -fPIC -fpie -fno-omit-frame-pointer -O2 -c $F.inst.bc -o $F.rsan.o
$DIR/third_party/llvm/build/bin/clang -fPIC -fpie -fno-omit-frame-pointer -O2 -c $F.bc -o $F.orig.o
		

LIBS=$(ldd $F | grep -o -P ' /[^ ]+' | tr '\n' ' ')
LINK_LIBS=


# Compile the runtime.
$DIR/third_party/llvm/build/bin/clang++ -fomit-frame-pointer -O2 -c $DIR/bin/Runtime.bc -o $F.runtime.o
INST_LINK_OBJS="${F}.runtime.o"
ORIG_LINK_OBJS=

# Figure out which libraries were produced by the build vs. which are
# part of the system. For those produced by the build, try to extract
# the bitcode so that we can instrument them.
for lib in $LIBS ; do
	echo "Found ${lib}"
	$DIR/third_party/whole-program-llvm/extract-bc $lib &>/dev/null
	if [[ $? -eq 0 ]] ; then
		echo " -> Found bitcode for ${lib}"

		$DIR/third_party/llvm/build/bin/opt -load $DIR/bin/libRaceSanitizer.so -rsan -O2 $lib.bc -o $lib.rsan.bc
		$DIR/third_party/llvm/build/bin/clang -fPIC -fno-omit-frame-pointer -O2 -c $lib.rsan.bc -o $lib.rsan.o
		$DIR/third_party/llvm/build/bin/clang -fPIC -shared $lib.rsan.o -o $lib.rsan.so

		INST_LINK_OBJS="${INST_LINK_OBJS} ${lib}.rsan.so"

		$DIR/third_party/llvm/build/bin/clang -fPIC -fno-omit-frame-pointer -O2 -c $lib.bc -o $lib.orig.o
		$DIR/third_party/llvm/build/bin/clang -fPIC -shared $lib.orig.o -o $lib.orig.so
		ORIG_LINK_OBJS="${ORIG_LINK_OBJS} ${lib}.orig.so"

	else
		LINK_LIBS="${LINK_LIBS} $lib"
	fi
done

echo "Linking original binary"
$DIR/third_party/llvm/build/bin/clang -fno-omit-frame-pointer -O2 -o $F.orig $F.orig.o $LDFLAGS $ORIG_LINK_OBJS $LINK_LIBS -lpthread -ldl
echo " -> Produced normal binary ${F}.orig"

echo "Linking instrumented binary"
$DIR/third_party/llvm/build/bin/clang++ -fno-omit-frame-pointer -O2 -o $F.rsan $F.rsan.o $LDFLAGS $INST_LINK_OBJS $LINK_LIBS -lpthread -ldl
echo " -> Produced instrumented binary ${F}.rsan"


