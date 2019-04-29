// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Low level raw interfaces to the sequence counter used by the VDSO.
#ifndef VDSO_SEQLOCK_H_
#define VDSO_SEQLOCK_H_

#include <stdint.h>

#include "vdso/barrier.h"
#include "vdso/compiler.h"

namespace vdso {

inline int32_t read_seqcount_begin(const uint64_t* s) {
  uint64_t seq = *s;
  read_barrier();
  return seq & ~1;
}

inline int read_seqcount_retry(const uint64_t* s, uint64_t seq) {
  read_barrier();
  return unlikely(*s != seq);
}

}  // namespace vdso

#endif  // VDSO_SEQLOCK_H_
