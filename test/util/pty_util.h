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

#ifndef GVISOR_TEST_UTIL_PTY_UTIL_H_
#define GVISOR_TEST_UTIL_PTY_UTIL_H_

#include <termios.h>

#include <ostream>

#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

// Opens the replica end of the passed master as R/W and nonblocking. It does
// not set the replica as the controlling TTY.
PosixErrorOr<FileDescriptor> OpenReplica(const FileDescriptor& master);

// Identical to the above OpenReplica, but flags are all specified by the
// caller.
PosixErrorOr<FileDescriptor> OpenReplica(const FileDescriptor& master,
                                         int flags);

// Get the number of the replica end of the master.
PosixErrorOr<int> ReplicaID(const FileDescriptor& master);

// glibc defines its own, different, version of struct termios. We care about
// what the kernel does, not glibc.
#define KERNEL_NCCS 19

struct kernel_termios {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[KERNEL_NCCS];
};

struct kernel_termios2 {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[KERNEL_NCCS];
  speed_t c_ispeed;
  speed_t c_ospeed;
};

#ifdef TCGETS2
#undef TCGETS2
#endif
#define TCGETS2 0x802c542a

#ifdef TCSETS2
#undef TCSETS2
#endif
#define TCSETS2 0x402c542b

#ifdef TCSETSW2
#undef TCSETSW2
#endif
#define TCSETSW2 0x402c542c

#ifdef TCSETSF2
#undef TCSETSF2
#endif
#define TCSETSF2 0x402c542d

bool operator==(struct kernel_termios const& a, struct kernel_termios const& b);

std::ostream& operator<<(std::ostream& os, struct kernel_termios const& a);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_PTY_UTIL_H_
