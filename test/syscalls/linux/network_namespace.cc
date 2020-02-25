// Copyright 2020 The gVisor Authors.
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

#include <net/if.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/synchronization/notification.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/memory_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

using TestFunc = std::function<PosixError()>;
using RunFunc = std::function<PosixError(TestFunc)>;

struct NamespaceStrategy {
  RunFunc run;

  static NamespaceStrategy Of(RunFunc run) {
    NamespaceStrategy s;
    s.run = run;
    return s;
  }
};

PosixError RunWithUnshare(TestFunc fn) {
  PosixError err = PosixError(-1, "function did not return a value");
  ScopedThread t([&] {
    if (unshare(CLONE_NEWNET) != 0) {
      err = PosixError(errno);
      return;
    }
    err = fn();
  });
  t.Join();
  return err;
}

PosixError RunWithClone(TestFunc fn) {
  struct Args {
    absl::Notification n;
    TestFunc fn;
    PosixError err;
  };
  Args args;
  args.fn = fn;
  args.err = PosixError(-1, "function did not return a value");

  ASSIGN_OR_RETURN_ERRNO(
      Mapping child_stack,
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  pid_t child = clone(
      +[](void *arg) {
        Args *args = reinterpret_cast<Args *>(arg);
        args->err = args->fn();
        args->n.Notify();
        syscall(SYS_exit, 0);  // Exit manually. No return address on stack.
        return 0;
      },
      reinterpret_cast<void *>(child_stack.addr() + kPageSize),
      CLONE_NEWNET | CLONE_THREAD | CLONE_SIGHAND | CLONE_VM, &args);
  if (child < 0) {
    return PosixError(errno, "clone() failed");
  }
  args.n.WaitForNotification();
  return args.err;
}

class NetworkNamespaceTest
    : public ::testing::TestWithParam<NamespaceStrategy> {};

TEST_P(NetworkNamespaceTest, LoopbackExists) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  EXPECT_NO_ERRNO(GetParam().run([]() {
    // TODO(gvisor.dev/issue/1833): Update this to test that only "lo" exists.
    // Check loopback device exists.
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
      return PosixError(errno, "socket() failed");
    }
    struct ifreq ifr;
    snprintf(ifr.ifr_name, IFNAMSIZ, "lo");
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
      return PosixError(errno, "ioctl() failed, lo cannot be found");
    }
    return NoError();
  }));
}

INSTANTIATE_TEST_SUITE_P(
    AllNetworkNamespaceTest, NetworkNamespaceTest,
    ::testing::Values(NamespaceStrategy::Of(RunWithUnshare),
                      NamespaceStrategy::Of(RunWithClone)));

}  // namespace

}  // namespace testing
}  // namespace gvisor
