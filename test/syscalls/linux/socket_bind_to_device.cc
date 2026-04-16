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
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_bind_to_device_util.h"
#include "test/util/capability_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

using std::string;

// Test fixture for SO_BINDTODEVICE tests.
class BindToDeviceTest : public ::testing::TestWithParam<SocketKind> {
 protected:
  void SetUp() override {
    printf("Testing case: %s\n", GetParam().description.c_str());

    interface_name_ = "eth1";
    auto interface_names = GetInterfaceNames();
    if (interface_names.find(interface_name_) == interface_names.end()) {
      // Need a tunnel.
      bool tunnel_created = false;
      if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN))) {
        tunnel_ = ASSERT_NO_ERRNO_AND_VALUE(Tunnel::New());
        interface_name_ = tunnel_->GetName();
        if (!interface_name_.empty()) {
          tunnel_created = true;
        }
      }
      
      if (!tunnel_created) {
        if (interface_names.find("lo") != interface_names.end()) {
          interface_name_ = "lo";
        } else {
          GTEST_SKIP() << "No suitable interface found";
        }
      }
    }
    socket_ = ASSERT_NO_ERRNO_AND_VALUE(GetParam().Create());
  }

  string interface_name() const { return interface_name_; }

  int socket_fd() const { return socket_->get(); }

 private:
  std::unique_ptr<Tunnel> tunnel_;
  string interface_name_;
  std::unique_ptr<FileDescriptor> socket_;
};

constexpr char kIllegalIfnameChar = '/';

// Tests getsockopt of the default value.
TEST_P(BindToDeviceTest, GetsockoptDefault) {
  char name_buffer[IFNAMSIZ * 2];
  char original_name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Read the default SO_BINDTODEVICE.
  memset(original_name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
  for (size_t i = 0; i <= sizeof(name_buffer); i++) {
    memset(name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
    name_buffer_size = i;
    EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE,
                           name_buffer, &name_buffer_size),
                SyscallSucceedsWithValue(0));
    EXPECT_EQ(name_buffer_size, 0);
    EXPECT_EQ(memcmp(name_buffer, original_name_buffer, sizeof(name_buffer)),
              0);
  }
}

// Tests setsockopt of invalid device name.
TEST_P(BindToDeviceTest, SetsockoptInvalidDeviceName) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Set an invalid device name.
  memset(name_buffer, kIllegalIfnameChar, 5);
  name_buffer_size = 5;
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         name_buffer_size),
              SyscallFailsWithErrno(ENODEV));
}

// Tests setsockopt of a buffer with a valid device name but not
// null-terminated, with different sizes of buffer.
TEST_P(BindToDeviceTest, SetsockoptValidDeviceNameWithoutNullTermination) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  // Intentionally overwrite the null at the end.
  memset(name_buffer + interface_name().size(), kIllegalIfnameChar,
         sizeof(name_buffer) - interface_name().size());
  for (size_t i = 1; i <= sizeof(name_buffer); i++) {
    name_buffer_size = i;
    SCOPED_TRACE(absl::StrCat("Buffer size: ", i));
    // It should only work if the size provided is exactly right.
    if (name_buffer_size == interface_name().size()) {
      EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, name_buffer_size),
                  SyscallSucceeds());
    } else {
      EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, name_buffer_size),
                  SyscallFailsWithErrno(ENODEV));
    }
  }
}

// Tests setsockopt of a buffer with a valid device name and null-terminated,
// with different sizes of buffer.
TEST_P(BindToDeviceTest, SetsockoptValidDeviceNameWithNullTermination) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  // Don't overwrite the null at the end.
  memset(name_buffer + interface_name().size() + 1, kIllegalIfnameChar,
         sizeof(name_buffer) - interface_name().size() - 1);
  for (size_t i = 1; i <= sizeof(name_buffer); i++) {
    auto socket = ASSERT_NO_ERRNO_AND_VALUE(GetParam().Create());
    name_buffer_size = i;
    SCOPED_TRACE(absl::StrCat("Buffer size: ", i));
    // It should only work if the size provided is at least the right size.
    if (name_buffer_size >= interface_name().size()) {
      EXPECT_THAT(setsockopt(socket->get(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, name_buffer_size),
                  SyscallSucceeds());
    } else {
      EXPECT_THAT(setsockopt(socket->get(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, name_buffer_size),
                  SyscallFailsWithErrno(ENODEV));
    }
  }
}

// Tests that setsockopt of an invalid device name doesn't unset the previous
// valid setsockopt.
TEST_P(BindToDeviceTest, SetsockoptValidThenInvalid) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    GTEST_SKIP() << "CAP_NET_RAW not available";
  }

  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Write successfully.
  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  ASSERT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallSucceeds());

  // Read it back successfully.
  memset(name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, interface_name().size() + 1);
  EXPECT_STREQ(name_buffer, interface_name().c_str());

  // Write unsuccessfully.
  memset(name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
  name_buffer_size = 5;
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallFailsWithErrno(ENODEV));

  // Read it back successfully, it's unchanged.
  memset(name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, interface_name().size() + 1);
  EXPECT_STREQ(name_buffer, interface_name().c_str());
}

// Tests that setsockopt of zero-length string correctly unsets the previous
// value.
TEST_P(BindToDeviceTest, SetsockoptValidThenClear) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    GTEST_SKIP() << "CAP_NET_RAW not available";
  }

  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Write successfully.
  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallSucceeds());

  // Read it back successfully.
  memset(name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, interface_name().size() + 1);
  EXPECT_STREQ(name_buffer, interface_name().c_str());

  // Clear it successfully.
  name_buffer_size = 0;
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         name_buffer_size),
              SyscallSucceeds());

  // Read it back successfully, it's cleared.
  memset(name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, 0);
}

// Tests that setsockopt of empty string correctly unsets the previous
// value.
TEST_P(BindToDeviceTest, SetsockoptValidThenClearWithNull) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    GTEST_SKIP() << "CAP_NET_RAW not available";
  }

  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Write successfully.
  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallSucceeds());

  // Read it back successfully.
  memset(name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, interface_name().size() + 1);
  EXPECT_STREQ(name_buffer, interface_name().c_str());

  // Clear it successfully.
  memset(name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
  name_buffer[0] = 0;
  name_buffer_size = sizeof(name_buffer);
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         name_buffer_size),
              SyscallSucceeds());

  // Read it back successfully, it's cleared.
  memset(name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, 0);
}

// Tests getsockopt with different buffer sizes.
TEST_P(BindToDeviceTest, GetsockoptDevice) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Write successfully.
  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  ASSERT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallSucceeds());

  // Read it back at various buffer sizes.
  for (size_t i = 0; i <= sizeof(name_buffer); i++) {
    memset(name_buffer, kIllegalIfnameChar, sizeof(name_buffer));
    name_buffer_size = i;
    SCOPED_TRACE(absl::StrCat("Buffer size: ", i));
    // Linux only allows a buffer at least IFNAMSIZ, even if less would suffice
    // for this interface name.
    if (name_buffer_size >= IFNAMSIZ) {
      EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, &name_buffer_size),
                  SyscallSucceeds());
      EXPECT_EQ(name_buffer_size, interface_name().size() + 1);
      EXPECT_STREQ(name_buffer, interface_name().c_str());
    } else {
      EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, &name_buffer_size),
                  SyscallFailsWithErrno(EINVAL));
      EXPECT_EQ(name_buffer_size, i);
    }
  }
}

// Tests that rebinding to another device fails without CAP_NET_RAW.
// Matches Linux net/core/sock.c:sock_setsockopt() where changing binding
// requires CAP_NET_RAW.
TEST_P(BindToDeviceTest, RebindFailWithoutCapNetRaw) {
  char name_buffer[IFNAMSIZ * 2];
  
  // Bind to initial device.
  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  ASSERT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallSucceeds());

  // Drop CAP_NET_RAW.
  AutoCapability cap(CAP_NET_RAW, false);

  char name_buffer2[IFNAMSIZ * 2];
  snprintf(name_buffer2, sizeof(name_buffer2), "%s", "lo");
  
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer2, sizeof(name_buffer2)),
              SyscallFailsWithErrno(EPERM));
}

// Matches Linux net/core/sock.c:sock_bindtoindex where rebinding to the
// same device requires CAP_NET_RAW.
TEST_P(BindToDeviceTest, RebindSameDeviceFailsWithoutCapNetRaw) {
  char name_buffer[IFNAMSIZ * 2];
  
  // Bind to initial device.
  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  ASSERT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallSucceeds());

  // Drop CAP_NET_RAW.
  AutoCapability cap(CAP_NET_RAW, false);

  // Attempt to bind to the SAME device again.
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallFailsWithErrno(EPERM));
}

// Matches Linux net/core/sock.c:sock_setsockopt() where changing binding
// succeeds with CAP_NET_RAW.
TEST_P(BindToDeviceTest, RebindSuccessWithCapNetRaw) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    GTEST_SKIP() << "CAP_NET_RAW not available";
  }

  char name_buffer[IFNAMSIZ * 2];
  
  // Bind to initial device.
  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  ASSERT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallSucceeds());

  // We already have CAP_NET_RAW by default in this fixture.
  
  char name_buffer2[IFNAMSIZ * 2];
  snprintf(name_buffer2, sizeof(name_buffer2), "%s", "lo");
  
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer2,
                         sizeof(name_buffer2)),
              SyscallSucceeds());
}

// Matches Linux net/core/sock.c:sock_bindtoindex where unbinding requires
// CAP_NET_RAW when already bound.
TEST_P(BindToDeviceTest, UnbindFailsWithoutCapNetRaw) {
  char name_buffer[IFNAMSIZ * 2];
  
  // Bind to initial device.
  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  ASSERT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallSucceeds());

  // Drop CAP_NET_RAW.
  AutoCapability cap(CAP_NET_RAW, false);

  // Attempt to unbind.
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         0),
              SyscallFailsWithErrno(EPERM));
}

TEST_P(BindToDeviceTest, UnbindSucceedsWithCapNetRaw) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    GTEST_SKIP() << "CAP_NET_RAW not available";
  }

  char name_buffer[IFNAMSIZ * 2];
  
  // Bind to initial device.
  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  ASSERT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         sizeof(name_buffer)),
              SyscallSucceeds());

  // We have CAP_NET_RAW by default.

  // Attempt to unbind.
  EXPECT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_BINDTODEVICE, name_buffer,
                         0),
              SyscallSucceeds());
}

// Matches Linux net/core/sock.c:sock_setsockopt() where binding new socket
// does not require CAP_NET_RAW.
TEST_P(BindToDeviceTest, BindNewSuccessWithoutCapNetRaw) {
  auto socket = ASSERT_NO_ERRNO_AND_VALUE(GetParam().Create());
  
  // Drop CAP_NET_RAW.
  AutoCapability cap(CAP_NET_RAW, false);

  char name_buffer[IFNAMSIZ * 2];
  snprintf(name_buffer, sizeof(name_buffer), "%s", interface_name().c_str());
  
  EXPECT_THAT(setsockopt(socket->get(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, sizeof(name_buffer)),
              SyscallSucceeds());
}

INSTANTIATE_TEST_SUITE_P(BindToDeviceTest, BindToDeviceTest,
                         ::testing::Values(IPv4UDPUnboundSocket(0),
                                           IPv4TCPUnboundSocket(0)));

}  // namespace testing
}  // namespace gvisor
