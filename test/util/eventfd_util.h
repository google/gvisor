// Copyright 2019 The gVisor Authors.
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

#ifndef GVISOR_TEST_UTIL_EVENTFD_UTIL_H_
#define GVISOR_TEST_UTIL_EVENTFD_UTIL_H_
#include <asm/unistd.h>
#include <sys/eventfd.h>

#include <cerrno>

#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"

namespace gvisor {
namespace testing {

// Returns a new eventfd with the given initial value and flags.
inline PosixErrorOr<FileDescriptor> NewEventFD(unsigned int initval = 0,
                                               int flags = 0) {
  int fd = eventfd(initval, flags);
  MaybeSave();
  if (fd < 0) {
    return PosixError(errno, "eventfd");
  }
  return FileDescriptor(fd);
}

// This is a wrapper for the eventfd2(2) system call.
inline int Eventdfd2Setup(unsigned int initval, int flags) {
  return syscall(__NR_eventfd2, initval, flags);
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_EVENTFD_UTIL_H_
