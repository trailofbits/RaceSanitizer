# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

cmake_minimum_required (VERSION 2.8)

list(APPEND CMAKE_MODULE_PATH "${RSAN_DIR}/third_party/llvm/build/share/llvm/cmake")

include(LLVMConfig)
include(AddLLVM)

add_definitions(${LLVM_DEFINITIONS})

include_directories(${LLVM_INCLUDE_DIRS})

add_compile_options(-std=c++11)
add_compile_options(-frtti)
add_compile_options(-g3)
add_compile_options(-Wall)
add_compile_options(-Werror)

add_library( RaceSanitizer SHARED Transform.cpp )

add_llvm_loadable_module(RaceSanitizer Transform.cpp)
