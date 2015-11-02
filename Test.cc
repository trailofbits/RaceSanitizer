/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstdlib>
#include <thread>
#include <functional>
#include <unistd.h>

#include <cstdint>

enum {
  kNumThreads = 6,
  kNumBits = 32
};

extern "C" void __rsan_read_1(uintptr_t);
extern "C" void __rsan_write_1(uintptr_t);
extern "C" void __rsan_record_alloc(uintptr_t, size_t);

static uint8_t counters[64];

void foo(void) {
  for (auto &c : counters) {
    __rsan_read_1(reinterpret_cast<uintptr_t>(&c));
    auto old_val = c;

    __rsan_write_1(reinterpret_cast<uintptr_t>(&c));
    c = old_val + 1;
  }
}

int main(void) {

  __rsan_record_alloc(reinterpret_cast<uintptr_t>(&(counters[0])),
                      sizeof counters);

  for (auto i = 0; i < kNumThreads; ++i) {
    std::thread t([] (void) {
      for (;;) {
        foo();
      }
    });
    t.detach();
  }
  sleep(20);
  exit(EXIT_SUCCESS);
}
