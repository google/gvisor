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

#include <arpa/inet.h>
#include <linux/capability.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/node_hash_map.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_bind_to_device_util.h"
#include "test/util/capability_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

using std::string;
using std::vector;

// Test fixture for SO_BINDTODEVICE tests the results of sequences of socket
// binding.
class BindToDeviceSequenceTest : public ::testing::TestWithParam<SocketKind> {
 protected:
  void SetUp() override {
    printf("Testing case: %s\n", GetParam().description.c_str());
    ASSERT_TRUE(ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)))
        << "CAP_NET_RAW is required to use SO_BINDTODEVICE";
    socket_factory_ = GetParam();

    interface_names_ = GetInterfaceNames();
  }

  PosixErrorOr<std::unique_ptr<FileDescriptor>> NewSocket() const {
    return socket_factory_.Create();
  }

  // Gets a device by device_id.  If the device_id has been seen before, returns
  // the previously returned device.  If not, finds or creates a new device.
  // Returns an empty string on failure.
  void GetDevice(int device_id, string* device_name) {
    auto device = devices_.find(device_id);
    if (device != devices_.end()) {
      *device_name = device->second;
      return;
    }

    // Need to pick a new device.  Try ethernet first.
    *device_name = absl::StrCat("eth", next_unused_eth_);
    if (interface_names_.find(*device_name) != interface_names_.end()) {
      devices_[device_id] = *device_name;
      next_unused_eth_++;
      return;
    }

    // Need to make a new tunnel device.  gVisor tests should have enough
    // ethernet devices to never reach here.
    ASSERT_FALSE(IsRunningOnGvisor());
    // Need a tunnel.
    tunnels_.push_back(ASSERT_NO_ERRNO_AND_VALUE(Tunnel::New()));
    devices_[device_id] = tunnels_.back()->GetName();
    *device_name = devices_[device_id];
  }

  // Release the socket
  void ReleaseSocket(int socket_id) {
    // Close the socket that was made in a previous action.  The socket_id
    // indicates which socket to close based on index into the list of actions.
    sockets_to_close_.erase(socket_id);
  }

  // SetDevice changes the bind_to_device option. It does not bind or re-bind.
  void SetDevice(int socket_id, int device_id) {
    auto socket_fd = sockets_to_close_[socket_id]->get();
    string device_name;
    ASSERT_NO_FATAL_FAILURE(GetDevice(device_id, &device_name));
    EXPECT_THAT(setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE,
                           device_name.c_str(), device_name.size() + 1),
                SyscallSucceedsWithValue(0));
  }

  // Bind a socket with the reuse options and bind_to_device options. Checks
  // that all steps succeed and that the bind command's error matches want.
  // Sets the socket_id to uniquely identify the socket bound if it is not
  // nullptr.
  void BindSocket(bool reuse_port, bool reuse_addr, int device_id = 0,
                  int want = 0, int* socket_id = nullptr) {
    next_socket_id_++;
    sockets_to_close_[next_socket_id_] = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
    auto socket_fd = sockets_to_close_[next_socket_id_]->get();
    if (socket_id != nullptr) {
      *socket_id = next_socket_id_;
    }

    // If reuse_port is indicated, do that.
    if (reuse_port) {
      EXPECT_THAT(setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                             sizeof(kSockOptOn)),
                  SyscallSucceedsWithValue(0));
    }

    // If reuse_addr is indicated, do that.
    if (reuse_addr) {
      EXPECT_THAT(setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                             sizeof(kSockOptOn)),
                  SyscallSucceedsWithValue(0));
    }

    // If the device is non-zero, bind to that device.
    if (device_id != 0) {
      string device_name;
      ASSERT_NO_FATAL_FAILURE(GetDevice(device_id, &device_name));
      EXPECT_THAT(setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE,
                             device_name.c_str(), device_name.size() + 1),
                  SyscallSucceedsWithValue(0));
      char get_device[100];
      socklen_t get_device_size = 100;
      EXPECT_THAT(getsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, get_device,
                             &get_device_size),
                  SyscallSucceedsWithValue(0));
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = port_;
    if (want == 0) {
      ASSERT_THAT(
          bind(socket_fd, reinterpret_cast<const struct sockaddr*>(&addr),
               sizeof(addr)),
          SyscallSucceeds());
    } else {
      ASSERT_THAT(
          bind(socket_fd, reinterpret_cast<const struct sockaddr*>(&addr),
               sizeof(addr)),
          SyscallFailsWithErrno(want));
    }

    if (port_ == 0) {
      // We don't yet know what port we'll be using so we need to fetch it and
      // remember it for future commands.
      socklen_t addr_size = sizeof(addr);
      ASSERT_THAT(
          getsockname(socket_fd, reinterpret_cast<struct sockaddr*>(&addr),
                      &addr_size),
          SyscallSucceeds());
      port_ = addr.sin_port;
    }
  }

 private:
  SocketKind socket_factory_;
  // devices maps from the device id in the test case to the name of the device.
  absl::node_hash_map<int, string> devices_;
  // These are the tunnels that were created for the test and will be destroyed
  // by the destructor.
  vector<std::unique_ptr<Tunnel>> tunnels_;
  // A list of all interface names before the test started.
  std::unordered_set<string> interface_names_;
  // The next ethernet device to use when requested a device.
  int next_unused_eth_ = 1;
  // The port for all tests.  Originally 0 (any) and later set to the port that
  // all further commands will use.
  in_port_t port_ = 0;
  // sockets_to_close_ is a map from action index to the socket that was
  // created.
  absl::node_hash_map<int,
                      std::unique_ptr<gvisor::testing::FileDescriptor>>
      sockets_to_close_;
  int next_socket_id_ = 0;
};

TEST_P(BindToDeviceSequenceTest, BindTwiceWithDeviceFails) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ false, /* reuse_addr */ false, /* bind_to_device */ 3));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 3, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindToDevice) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ false, /* reuse_addr */ false, /* bind_to_device */ 1));
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ false, /* reuse_addr */ false, /* bind_to_device */ 2));
}

TEST_P(BindToDeviceSequenceTest, BindToDeviceAndThenWithoutDevice) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindWithoutDevice) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindWithDevice) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123, 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 456, 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 789, 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindWithReuse) {
  ASSERT_NO_FATAL_FAILURE(
      BindSocket(/* reusePort */ true, /* reuse_addr */ false));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false,
      /* bind_to_device */ 123));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false, /* bind_to_device */ 0));
}

TEST_P(BindToDeviceSequenceTest, BindingWithReuseAndDevice) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false, /* bind_to_device */ 123));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false, /* bind_to_device */ 123));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false, /* bind_to_device */ 456));
  ASSERT_NO_FATAL_FAILURE(
      BindSocket(/* reuse_port */ true, /* reuse_addr */ false));
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false, /* bind_to_device */ 789));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 999, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, MixingReuseAndNotReuseByBindingToDevice) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123, 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 456, 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 789, 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 999, 0));
}

TEST_P(BindToDeviceSequenceTest, CannotBindTo0AfterMixingReuseAndNotReuse) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false, /* bind_to_device */ 123));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 456));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindAndRelease) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false, /* bind_to_device */ 123));
  int to_release;
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, 0, &to_release));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 345, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false, /* bind_to_device */ 789));
  // Release the bind to device 0 and try again.
  ASSERT_NO_FATAL_FAILURE(ReleaseSocket(to_release));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 345));
}

TEST_P(BindToDeviceSequenceTest, BindTwiceWithReuseOnce) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindWithReuseAddr) {
  ASSERT_NO_FATAL_FAILURE(
      BindSocket(/* reusePort */ false, /* reuse_addr */ true));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 123, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ false, /* reuse_addr */ true, /* bind_to_device */ 123));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ false, /* reuse_addr */ true, /* bind_to_device */ 0));
}

TEST_P(BindToDeviceSequenceTest,
       CannotBindTo0AfterMixingReuseAddrAndNotReuseAddr) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false, /* bind_to_device */ 123));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 456));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindReuseAddrReusePortThenReusePort) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindReuseAddrReusePortThenReuseAddr) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindDoubleReuseAddrReusePortThenReusePort) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ true, /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindDoubleReuseAddrReusePortThenReuseAddr) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ true, /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindReusePortThenReuseAddrReusePort) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ true, /* reuse_addr */ false, /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest, BindReuseAddrThenReuseAddr) {
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ false, /* reuse_addr */ true, /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0, EADDRINUSE));
}

TEST_P(BindToDeviceSequenceTest,
       BindReuseAddrThenReuseAddrReusePortThenReuseAddr) {
  // The behavior described in this test seems like a Linux bug. It doesn't
  // make any sense and it is unlikely that any applications rely on it.
  //
  // Both SO_REUSEADDR and SO_REUSEPORT allow binding multiple UDP sockets to
  // the same address and deliver each packet to exactly one of the bound
  // sockets. If both are enabled, one of the strategies is selected to route
  // packets. The strategy is selected dynamically based on the settings of the
  // currently bound sockets. Usually, the strategy is selected based on the
  // common setting (SO_REUSEADDR or SO_REUSEPORT) amongst the sockets, but for
  // some reason, Linux allows binding sets of sockets with no overlapping
  // settings in some situations. In this case, it is not obvious which strategy
  // would be selected as the configured setting is a contradiction.
  SKIP_IF(IsRunningOnGvisor());

  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ false, /* reuse_addr */ true, /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ true,
                                     /* bind_to_device */ 0));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ true,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 0));
}

// Repro test for gvisor.dev/issue/1217. Not replicated in ports_test.go as this
// test is different from the others and wouldn't fit well there.
TEST_P(BindToDeviceSequenceTest, BindAndReleaseDifferentDevice) {
  int to_release;
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 3, 0, &to_release));
  ASSERT_NO_FATAL_FAILURE(BindSocket(/* reuse_port */ false,
                                     /* reuse_addr */ false,
                                     /* bind_to_device */ 3, EADDRINUSE));
  // Change the device. Since the socket was already bound, this should have no
  // effect.
  SetDevice(to_release, 2);
  // Release the bind to device 3 and try again.
  ASSERT_NO_FATAL_FAILURE(ReleaseSocket(to_release));
  ASSERT_NO_FATAL_FAILURE(BindSocket(
      /* reuse_port */ false, /* reuse_addr */ false, /* bind_to_device */ 3));
}

INSTANTIATE_TEST_SUITE_P(BindToDeviceTest, BindToDeviceSequenceTest,
                         ::testing::Values(IPv4UDPUnboundSocket(0),
                                           IPv4TCPUnboundSocket(0)));

}  // namespace testing
}  // namespace gvisor
