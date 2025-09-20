// Copyright (c) 2025 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include <cstdint>
struct RegSet {
   std::uintmax_t value;
   RegSet( std::uintmax_t value_) : value(value_) {}
   template<typename Arg> void operator() (Arg &arg) { 
      arg = value;
   }
};

#ifdef __x86_64__
#include "x86_64.cc"
#endif
#ifdef __aarch64__
#include "aarch64.cc"
#endif
#ifdef __i386__
#include "i386.cc"
#endif
