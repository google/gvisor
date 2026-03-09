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

#ifdef __linux__

#include <linux/capability.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <cerrno>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<bool> HaveRawIPSocketCapability(int family, int protocol) {
  // Note that we can't just use HaveCapability(CAP_NET_RAW) because raw socket
  // capability check is done using `ns_capable(net->user_ns, CAP_NET_RAW)` (on
  // the network namespace's user namespace, which the test process may not be a
  // part of). The only feasible way to check CAP_NET_RAW is to try to open a
  // raw socket and see if it returns EPERM.
  auto fd = Socket(family, SOCK_RAW, protocol);
  if (fd.ok()) {
    return true;
  }
  int err = fd.error().errno_value();
  if (err == EPERM) {
    return false;
  }
  return PosixError(
      err, absl::StrCat("socket(", family == AF_INET ? "AF_INET" : "AF_INET6",
                        ", SOCK_RAW, ", protocol,
                        ") failed with "
                        "non-EPERM error, can not determine "
                        "CAP_NET_RAW capability"));
}

PosixErrorOr<bool> HavePacketSocketCapability(int type, int protocol) {
  // Note that we can't just use HaveCapability(CAP_NET_RAW) because packet
  // socket capability check is done using `ns_capable(net->user_ns,
  // CAP_NET_RAW)` (on the network namespace's user namespace, which the test
  // process may not be a part of). The only feasible way to check CAP_NET_RAW
  // is to try to open a raw socket and see if it returns EPERM.
  auto fd = Socket(AF_PACKET, type, htons(protocol));
  if (fd.ok()) {
    return true;
  }
  int err = fd.error().errno_value();
  if (err == EPERM) {
    return false;
  }
  return PosixError(
      err, absl::StrCat(
               "socket(AF_PACKET, ", type, ", ", protocol,
               ") failed with "
               "non-EPERM error, can not determine CAP_NET_RAW capability"));
}

PosixErrorOr<bool> CanCreateUserNamespace() {
  // The most reliable way to determine if userns creation is possible is by
  // trying to create one; see below.
  ASSIGN_OR_RETURN_ERRNO(
      auto child_stack,
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  int const child_pid = clone(
      +[](void*) { return 0; },
      reinterpret_cast<void*>(child_stack.addr() + kPageSize),
      CLONE_NEWUSER | SIGCHLD, /* arg = */ nullptr);
  if (child_pid > 0) {
    int status;
    int const ret = waitpid(child_pid, &status, /* options = */ 0);
    MaybeSave();
    if (ret < 0) {
      return PosixError(errno, "waitpid");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      return PosixError(
          ESRCH, absl::StrCat("child process exited with status ", status));
    }
    return true;
  } else if (errno == EPERM) {
    // Per clone(2), EPERM can be returned if:
    //
    // - "CLONE_NEWUSER was specified in flags, but either the effective user ID
    // or the effective group ID of the caller does not have a mapping in the
    // parent namespace (see user_namespaces(7))."
    //
    // - "(since Linux 3.9) CLONE_NEWUSER was specified in flags and the caller
    // is in a chroot environment (i.e., the caller's root directory does
    // not match the root directory of the mount namespace in which it
    // resides)."
    std::cerr << "clone(CLONE_NEWUSER) failed with EPERM" << std::endl;
    return false;
  } else if (errno == EUSERS) {
    // "(since Linux 3.11) CLONE_NEWUSER was specified in flags, and the call
    // would cause the limit on the number of nested user namespaces to be
    // exceeded. See user_namespaces(7)."
    std::cerr << "clone(CLONE_NEWUSER) failed with EUSERS" << std::endl;
    return false;
  } else {
    // Unexpected error code; indicate an actual error.
    return PosixError(errno, "clone(CLONE_NEWUSER)");
  }
}

}  // namespace testing
}  // namespace gvisor

#endif  // __linux__
