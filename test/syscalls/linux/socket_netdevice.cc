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

#include <linux/ethtool.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "gtest/gtest.h"
#include "absl/base/internal/endian.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

// Tests for netdevice queries.

namespace gvisor {
namespace testing {

namespace {

using ::testing::AnyOf;
using ::testing::Eq;

TEST(NetdeviceTest, Loopback) {
  SKIP_IF(IsRunningWithHostinet());
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  // Prepare the request.
  struct ifreq ifr;
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");

  // Check for a non-zero interface index.
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFINDEX, &ifr), SyscallSucceeds());
  EXPECT_NE(ifr.ifr_ifindex, 0);

  // Check that the loopback is zero hardware address.
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFHWADDR, &ifr), SyscallSucceeds());
  EXPECT_EQ(ifr.ifr_hwaddr.sa_family, ARPHRD_LOOPBACK);
  EXPECT_EQ(ifr.ifr_hwaddr.sa_data[0], 0);
  EXPECT_EQ(ifr.ifr_hwaddr.sa_data[1], 0);
  EXPECT_EQ(ifr.ifr_hwaddr.sa_data[2], 0);
  EXPECT_EQ(ifr.ifr_hwaddr.sa_data[3], 0);
  EXPECT_EQ(ifr.ifr_hwaddr.sa_data[4], 0);
  EXPECT_EQ(ifr.ifr_hwaddr.sa_data[5], 0);
}

TEST(NetdeviceTest, Netmask) {
  SKIP_IF(IsRunningWithHostinet());
  // We need an interface index to identify the loopback device.
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  struct ifreq ifr;
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFINDEX, &ifr), SyscallSucceeds());
  EXPECT_NE(ifr.ifr_ifindex, 0);

  // Use a netlink socket to get the netmask, which we'll then compare to the
  // netmask obtained via ioctl.
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  uint32_t port = ASSERT_NO_ERRNO_AND_VALUE(NetlinkPortID(fd.get()));

  struct request {
    struct nlmsghdr hdr;
    struct rtgenmsg rgm;
  };

  constexpr uint32_t kSeq = 12345;

  struct request req;
  req.hdr.nlmsg_len = sizeof(req);
  req.hdr.nlmsg_type = RTM_GETADDR;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = kSeq;
  req.rgm.rtgen_family = AF_UNSPEC;

  // Iterate through messages until we find the one containing the prefix length
  // (i.e. netmask) for the loopback device.
  int prefixlen = -1;
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      fd, &req, sizeof(req),
      [&](const struct nlmsghdr* hdr) {
        EXPECT_THAT(hdr->nlmsg_type, AnyOf(Eq(RTM_NEWADDR), Eq(NLMSG_DONE)));

        EXPECT_TRUE((hdr->nlmsg_flags & NLM_F_MULTI) == NLM_F_MULTI)
            << std::hex << hdr->nlmsg_flags;

        EXPECT_EQ(hdr->nlmsg_seq, kSeq);
        EXPECT_EQ(hdr->nlmsg_pid, port);

        if (hdr->nlmsg_type != RTM_NEWADDR) {
          return;
        }

        // RTM_NEWADDR contains at least the header and ifaddrmsg.
        EXPECT_GE(hdr->nlmsg_len, sizeof(*hdr) + sizeof(struct ifaddrmsg));

        struct ifaddrmsg* ifaddrmsg =
            reinterpret_cast<struct ifaddrmsg*>(NLMSG_DATA(hdr));
        if (ifaddrmsg->ifa_index == static_cast<uint32_t>(ifr.ifr_ifindex) &&
            ifaddrmsg->ifa_family == AF_INET) {
          prefixlen = ifaddrmsg->ifa_prefixlen;
        }
      },
      false));

  ASSERT_GE(prefixlen, 0);

  // Netmask is stored big endian in struct sockaddr_in, so we do the same for
  // comparison.
  uint32_t mask = 0xffffffff << (32 - prefixlen);
  mask = absl::gbswap_32(mask);

  // Check that the loopback interface has the correct subnet mask.
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFNETMASK, &ifr), SyscallSucceeds());
  EXPECT_EQ(ifr.ifr_netmask.sa_family, AF_INET);
  struct sockaddr_in* sin =
      reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
  EXPECT_EQ(sin->sin_addr.s_addr, mask);
}

TEST(NetdeviceTest, InterfaceName) {
  SKIP_IF(IsRunningWithHostinet());
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  // Prepare the request.
  struct ifreq ifr;
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");

  // Check for a non-zero interface index.
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFINDEX, &ifr), SyscallSucceeds());
  EXPECT_NE(ifr.ifr_ifindex, 0);

  // Check that SIOCGIFNAME finds the loopback interface.
  snprintf(ifr.ifr_name, IFNAMSIZ, "foo");
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFNAME, &ifr), SyscallSucceeds());
  EXPECT_STREQ(ifr.ifr_name, "lo");
}

TEST(NetdeviceTest, InterfaceFlags) {
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  // Prepare the request.
  struct ifreq ifr;
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");

  // Check that SIOCGIFFLAGS marks the interface with IFF_LOOPBACK, IFF_UP, and
  // IFF_RUNNING.
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFFLAGS, &ifr), SyscallSucceeds());
  EXPECT_EQ(ifr.ifr_flags & IFF_UP, IFF_UP);
  EXPECT_EQ(ifr.ifr_flags & IFF_RUNNING, IFF_RUNNING);
}

TEST(NetdeviceTest, InterfaceMTU) {
  SKIP_IF(IsRunningWithHostinet());
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  // Prepare the request.
  struct ifreq ifr = {};
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");

  // Check that SIOCGIFMTU returns a nonzero MTU.
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFMTU, &ifr), SyscallSucceeds());
  EXPECT_GT(ifr.ifr_mtu, 0);

  // Check that SIOCSIFMTU succeeds setting with same MTU as retrieved by
  // SIOCGIFMTU.
  // TODO(gvisor.dev/issue/6033): Support setting MTU value.
  ASSERT_THAT(ioctl(sock.get(), SIOCSIFMTU, &ifr), SyscallSucceeds());

  if (IsRunningOnGVisor()) {
    ifr.MTU += 1;
    ASSERT_THAT(ioctl(sock.get(), SIOCSIFMTU, &ifr),
                SyscallFailsWithErrno(EOPNOTSUPP));
    ifr.MTU -= 2;
    ASSERT_THAT(ioctl(sock.get(), SIOCSIFMTU, &ifr),
                SyscallFailsWithErrno(EOPNOTSUPP));
    ifr.MTU = 0;
    ASSERT_THAT(ioctl(sock.get(), SIOCSIFMTU, &ifr),
                SyscallFailsWithErrno(EOPNOTSUPP));
  }
}

TEST(NetdeviceTest, EthtoolGetTSInfo) {
  SKIP_IF(IsRunningWithHostinet());
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  struct ethtool_ts_info tsi = {};
  tsi.cmd = ETHTOOL_GET_TS_INFO;  // Get NIC's Timestamping capabilities.

  // Prepare the request.
  struct ifreq ifr = {};
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");
  ifr.ifr_data = (void*)&tsi;

  // Check that SIOCGIFMTU returns a nonzero MTU.
  if (IsRunningOnGvisor()) {
    ASSERT_THAT(ioctl(sock.get(), SIOCETHTOOL, &ifr),
                SyscallFailsWithErrno(EOPNOTSUPP));
    return;
  }
  ASSERT_THAT(ioctl(sock.get(), SIOCETHTOOL, &ifr), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
