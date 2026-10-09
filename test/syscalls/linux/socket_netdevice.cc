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

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <ios>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// Tests for netdevice queries.

namespace gvisor {
namespace testing {

namespace {

using ::testing::AnyOf;
using ::testing::Eq;

class NetdeviceNamespaceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(IsRunningWithHostinet());
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
    original_namespace_ =
        FileDescriptor(open("/proc/thread-self/ns/net", O_RDONLY));
    ASSERT_GE(original_namespace_.get(), 0);
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceeds());
    socket_ = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  }

  void TearDown() override {
    if (original_namespace_.get() >= 0) {
      EXPECT_THAT(setns(original_namespace_.get(), CLONE_NEWNET),
                  SyscallSucceeds());
    }
  }

  int Flags(int fd) {
    struct ifreq req = {};
    snprintf(req.ifr_name, IFNAMSIZ, "lo");
    EXPECT_THAT(ioctl(fd, SIOCGIFFLAGS, &req), SyscallSucceeds());
    return static_cast<unsigned short>(req.ifr_flags);
  }

  void SetFlags(int fd, int flags) {
    struct ifreq req = {};
    snprintf(req.ifr_name, IFNAMSIZ, "lo");
    req.ifr_flags = flags;
    ASSERT_THAT(ioctl(fd, SIOCSIFFLAGS, &req), SyscallSucceeds());
  }

  struct LinkAttribute {
    uint16_t type;
    uint32_t value;
    uint16_t size = sizeof(uint32_t);
  };

  PosixError ChangeLink(uint32_t flags, uint32_t change,
                        std::initializer_list<LinkAttribute> attributes = {}) {
    struct ifreq iface = {};
    snprintf(iface.ifr_name, IFNAMSIZ, "lo");
    if (ioctl(fd(), SIOCGIFINDEX, &iface) < 0) {
      return PosixError(errno, "SIOCGIFINDEX");
    }
    std::vector<char> request(NLMSG_LENGTH(sizeof(struct ifinfomsg)), 0);
    for (const auto& attribute : attributes) {
      const size_t offset = request.size();
      request.resize(offset + RTA_SPACE(attribute.size), 0);
      struct rtattr attr = {};
      attr.rta_type = attribute.type;
      attr.rta_len = RTA_LENGTH(attribute.size);
      memcpy(request.data() + offset, &attr, sizeof(attr));
      memcpy(request.data() + offset + RTA_LENGTH(0), &attribute.value,
             attribute.size);
    }
    auto* header = reinterpret_cast<struct nlmsghdr*>(request.data());
    constexpr uint32_t kSeq = 1;
    header->nlmsg_len = request.size();
    header->nlmsg_type = RTM_NEWLINK;
    header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    header->nlmsg_seq = kSeq;
    auto* info = reinterpret_cast<struct ifinfomsg*>(NLMSG_DATA(header));
    info->ifi_index = iface.ifr_ifindex;
    info->ifi_flags = flags;
    info->ifi_change = change;
    ASSIGN_OR_RETURN_ERRNO(FileDescriptor netlink,
                           NetlinkBoundSocket(NETLINK_ROUTE));
    return NetlinkRequestAckOrError(netlink, kSeq, request.data(),
                                    request.size());
  }

  int MTU() {
    struct ifreq req = {};
    snprintf(req.ifr_name, IFNAMSIZ, "lo");
    EXPECT_THAT(ioctl(fd(), SIOCGIFMTU, &req), SyscallSucceeds());
    return req.ifr_mtu;
  }

  int IPv4AddressCount() {
    struct ifreq addresses[4] = {};
    struct ifconf config = {};
    config.ifc_len = sizeof(addresses);
    config.ifc_req = addresses;
    EXPECT_THAT(ioctl(fd(), SIOCGIFCONF, &config), SyscallSucceeds());
    return config.ifc_len / sizeof(struct ifreq);
  }

  PosixError BindIPv6Loopback() {
    ASSIGN_OR_RETURN_ERRNO(FileDescriptor ipv6,
                           Socket(AF_INET6, SOCK_DGRAM, 0));
    struct sockaddr_in6 address = {};
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_loopback;
    if (bind(ipv6.get(), reinterpret_cast<struct sockaddr*>(&address),
             sizeof(address)) < 0) {
      return PosixError(errno, "bind");
    }
    return NoError();
  }

  int fd() const { return socket_.get(); }

 private:
  const DisableSave disable_save_;
  FileDescriptor original_namespace_;
  FileDescriptor socket_;
};

// A new loopback has no addresses; setting IFF_UP adds 127.0.0.1 and ::1.
TEST_F(NetdeviceNamespaceTest, LoopbackUpInitializesAddress) {
  EXPECT_EQ(Flags(fd()) & (IFF_UP | IFF_RUNNING), 0);
  EXPECT_EQ(IPv4AddressCount(), 0);
  EXPECT_THAT(BindIPv6Loopback(), PosixErrorIs(EADDRNOTAVAIL));
  SetFlags(fd(), Flags(fd()) | IFF_UP);
  EXPECT_EQ(Flags(fd()) & (IFF_UP | IFF_RUNNING | IFF_LOOPBACK),
            IFF_UP | IFF_RUNNING | IFF_LOOPBACK);
  struct ifreq req = {};
  snprintf(req.ifr_name, IFNAMSIZ, "lo");
  ASSERT_THAT(ioctl(fd(), SIOCGIFADDR, &req), SyscallSucceeds());
  const auto* address =
      reinterpret_cast<const struct sockaddr_in*>(&req.ifr_addr);
  EXPECT_EQ(address->sin_addr.s_addr, htonl(INADDR_LOOPBACK));
  EXPECT_NO_ERRNO(BindIPv6Loopback());
}

// UP keeps an address configured while DOWN and adds 127.0.0.1 without
// duplicating the 127.0.0.0/8 route.
TEST_F(NetdeviceNamespaceTest, LoopbackUpKeepsConfiguredAddress) {
  struct ifreq iface = {};
  snprintf(iface.ifr_name, IFNAMSIZ, "lo");
  ASSERT_THAT(ioctl(fd(), SIOCGIFINDEX, &iface), SyscallSucceeds());

  FileDescriptor netlink =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  constexpr uint32_t kSeq = 1;
  struct {
    struct nlmsghdr header;
    struct ifaddrmsg address;
    struct rtattr attr;
    struct in_addr local;
  } request = {};
  request.header.nlmsg_len = sizeof(request);
  request.header.nlmsg_type = RTM_NEWADDR;
  request.header.nlmsg_flags =
      NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
  request.header.nlmsg_seq = kSeq;
  request.address.ifa_family = AF_INET;
  request.address.ifa_prefixlen = 8;
  // Linux adds 127.0.0.1 on UP only if same-subnet addresses share its scope.
  request.address.ifa_scope = RT_SCOPE_HOST;
  request.address.ifa_index = iface.ifr_ifindex;
  request.attr.rta_len = RTA_LENGTH(sizeof(request.local));
  request.attr.rta_type = IFA_LOCAL;
  request.local.s_addr = htonl(INADDR_LOOPBACK + 1);
  ASSERT_NO_ERRNO(
      NetlinkRequestAckOrError(netlink, kSeq, &request, sizeof(request)));

  SetFlags(fd(), IFF_UP);
  EXPECT_EQ(IPv4AddressCount(), 2);

  struct {
    struct nlmsghdr header;
    struct rtmsg route;
  } dump = {};
  dump.header.nlmsg_len = sizeof(dump);
  dump.header.nlmsg_type = RTM_GETROUTE;
  dump.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  dump.header.nlmsg_seq = kSeq + 1;
  dump.route.rtm_family = AF_INET;
  constexpr in_addr_t kLoopbackNet = 0x7f000000;
  int routes = 0;
  ASSERT_NO_ERRNO(NetlinkRequestResponse(
      netlink, &dump, sizeof(dump),
      [&](const struct nlmsghdr* header) {
        if (header->nlmsg_type != RTM_NEWROUTE) {
          return;
        }
        const auto* route =
            reinterpret_cast<const struct rtmsg*>(NLMSG_DATA(header));
        if (route->rtm_family != AF_INET || route->rtm_dst_len != 8) {
          return;
        }
        int length = RTM_PAYLOAD(header);
        for (const struct rtattr* attr = RTM_RTA(route); RTA_OK(attr, length);
             attr = RTA_NEXT(attr, length)) {
          in_addr_t destination;
          if (attr->rta_type != RTA_DST ||
              RTA_PAYLOAD(attr) != sizeof(destination)) {
            continue;
          }
          memcpy(&destination, RTA_DATA(attr), sizeof(destination));
          if (destination == htonl(kLoopbackNet)) {
            ++routes;
          }
        }
      },
      false));
  EXPECT_EQ(routes, 1);
}

// Repeated UP and DOWN requests preserve device identity and actual state.
TEST_F(NetdeviceNamespaceTest, LoopbackRepeatedUpDown) {
  for (int i = 0; i < 3; ++i) {
    SetFlags(fd(), IFF_UP);
    SetFlags(fd(), IFF_UP);
    EXPECT_EQ(Flags(fd()) & (IFF_UP | IFF_RUNNING), IFF_UP | IFF_RUNNING);
    SetFlags(fd(), IFF_RUNNING);
    SetFlags(fd(), 0);
    EXPECT_EQ(Flags(fd()) & (IFF_UP | IFF_RUNNING), 0);
    EXPECT_EQ(Flags(fd()) & IFF_LOOPBACK, IFF_LOOPBACK);
  }
}

// An UP request on an enabled interface preserves userspace address removal.
TEST_F(NetdeviceNamespaceTest, RepeatedUpPreservesDeletedAddress) {
  SetFlags(fd(), IFF_UP);
  struct ifreq iface = {};
  snprintf(iface.ifr_name, IFNAMSIZ, "lo");
  ASSERT_THAT(ioctl(fd(), SIOCGIFINDEX, &iface), SyscallSucceeds());

  FileDescriptor netlink =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  constexpr uint32_t kSeq = 1;
  struct {
    struct nlmsghdr header;
    struct ifaddrmsg address;
    struct rtattr attr;
    struct in_addr local;
  } request = {};
  request.header.nlmsg_len = sizeof(request);
  request.header.nlmsg_type = RTM_DELADDR;
  request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  request.header.nlmsg_seq = kSeq;
  request.address.ifa_family = AF_INET;
  request.address.ifa_prefixlen = 8;
  request.address.ifa_index = iface.ifr_ifindex;
  request.attr.rta_len = RTA_LENGTH(sizeof(request.local));
  request.attr.rta_type = IFA_LOCAL;
  request.local.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_NO_ERRNO(
      NetlinkRequestAckOrError(netlink, kSeq, &request, sizeof(request)));

  auto address_bytes = [&] {
    struct ifreq addresses[4] = {};
    struct ifconf config = {};
    config.ifc_len = sizeof(addresses);
    config.ifc_req = addresses;
    EXPECT_THAT(ioctl(fd(), SIOCGIFCONF, &config), SyscallSucceeds());
    return config.ifc_len;
  };
  EXPECT_EQ(address_bytes(), 0);
  SetFlags(fd(), IFF_UP);
  EXPECT_EQ(address_bytes(), 0);

  struct {
    struct nlmsghdr header;
    struct ifinfomsg info;
  } up = {};
  up.header.nlmsg_len = sizeof(up);
  up.header.nlmsg_type = RTM_NEWLINK;
  up.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  up.header.nlmsg_seq = kSeq + 1;
  up.info.ifi_index = iface.ifr_ifindex;
  up.info.ifi_flags = IFF_UP;
  up.info.ifi_change = IFF_UP;
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(netlink, kSeq + 1, &up, sizeof(up)));
  EXPECT_EQ(address_bytes(), 0);

  SetFlags(fd(), 0);
  SetFlags(fd(), IFF_UP);
  EXPECT_EQ(address_bytes(), sizeof(struct ifreq));
}

// Netlink applies only selected bits; zero change retains legacy semantics.
TEST_F(NetdeviceNamespaceTest, NetlinkFlagMasks) {
  ASSERT_NO_ERRNO(ChangeLink(IFF_UP, 0));
  ASSERT_NE(Flags(fd()) & IFF_UP, 0);
  ASSERT_NO_ERRNO(ChangeLink(Flags(fd()), ~uint32_t{0}));
  ASSERT_NO_ERRNO(ChangeLink(0, IFF_DEBUG | IFF_PROMISC));
  EXPECT_NE(Flags(fd()) & IFF_UP, 0);
  ASSERT_NO_ERRNO(ChangeLink(IFF_PROMISC, IFF_UP));
  EXPECT_EQ(Flags(fd()) & (IFF_UP | IFF_PROMISC), 0);
  ASSERT_NO_ERRNO(ChangeLink(IFF_UP, IFF_PROMISC));
  EXPECT_EQ(Flags(fd()) & IFF_UP, 0);
  ASSERT_NO_ERRNO(ChangeLink(IFF_UP, IFF_UP));
  ASSERT_NO_ERRNO(ChangeLink(0, 0));
  EXPECT_NE(Flags(fd()) & IFF_UP, 0);
  ASSERT_NO_ERRNO(ChangeLink(IFF_LOOPBACK, 0));
  EXPECT_EQ(Flags(fd()) & IFF_UP, 0);
}

// Unsupported writable flags fail before either flags or attributes change.
TEST_F(NetdeviceNamespaceTest, UnsupportedFlagChanges) {
  SKIP_IF(!IsRunningOnGvisor());
  SetFlags(fd(), IFF_UP);
  const int old_flags = Flags(fd());
  const int old_mtu = MTU();
  for (int bit :
       {IFF_DEBUG, IFF_NOTRAILERS, IFF_NOARP, IFF_PROMISC, IFF_ALLMULTI,
        IFF_MULTICAST, IFF_PORTSEL, IFF_AUTOMEDIA, IFF_DYNAMIC}) {
    SCOPED_TRACE(bit);
    struct ifreq req = {};
    snprintf(req.ifr_name, IFNAMSIZ, "lo");
    req.ifr_flags = (old_flags & ~IFF_UP) ^ bit;
    EXPECT_THAT(ioctl(fd(), SIOCSIFFLAGS, &req),
                SyscallFailsWithErrno(EOPNOTSUPP));
    EXPECT_EQ(Flags(fd()), old_flags);
    EXPECT_THAT(ChangeLink(bit, IFF_UP | bit, {{IFLA_MTU, 1500}}),
                PosixErrorIs(EOPNOTSUPP, ::testing::_));
    EXPECT_EQ(Flags(fd()), old_flags);
    EXPECT_EQ(MTU(), old_mtu);
  }
}

// A malformed early attribute must not bring the interface UP.
TEST_F(NetdeviceNamespaceTest, MalformedLinkAttributePreservesFlags) {
  const int old_mtu = MTU();
  EXPECT_THAT(
      ChangeLink(IFF_UP, IFF_UP, {{IFLA_MTU, 1500}, {IFLA_ADDRESS, 0, 1}}),
      PosixErrorIs(EINVAL, ::testing::_));
  EXPECT_EQ(Flags(fd()) & IFF_UP, 0);
  EXPECT_EQ(MTU(), old_mtu);
}

// Attribute policy validation precedes all device changes, even for MASTER.
TEST_F(NetdeviceNamespaceTest, MalformedMasterPreservesFlagsAndMTU) {
  const int old_mtu = MTU();
  EXPECT_THAT(
      ChangeLink(IFF_UP, IFF_UP, {{IFLA_MTU, 1500}, {IFLA_MASTER, 0, 1}}),
      PosixErrorIs(AnyOf(Eq(EINVAL), Eq(ERANGE)), ::testing::_));
  EXPECT_EQ(Flags(fd()) & IFF_UP, 0);
  EXPECT_EQ(MTU(), old_mtu);
}

// A later MASTER failure retains the earlier MTU and UP changes, independent
// of the order of attributes in the request.
TEST_F(NetdeviceNamespaceTest, MasterFailureRetainsEarlierChanges) {
  for (bool master_first : {false, true}) {
    SetFlags(fd(), 0);
    const int old_mtu = MTU();
    const uint32_t mtu = master_first ? 1600 : 1500;
    const LinkAttribute master = {IFLA_MASTER, 0x7fffffff};
    const LinkAttribute mtu_attr = {IFLA_MTU, mtu};
    const auto result = master_first
                            ? ChangeLink(IFF_UP, IFF_UP, {master, mtu_attr})
                            : ChangeLink(IFF_UP, IFF_UP, {mtu_attr, master});
    // The existing missing-master errno differs between the two stacks.
    EXPECT_THAT(result, PosixErrorIs(IsRunningOnGvisor() ? ENODEV : EINVAL,
                                     ::testing::_));
    // Check ordering independently of the existing Ethernet MTU adjustment.
    EXPECT_NE(MTU(), old_mtu);
    EXPECT_NE(Flags(fd()) & IFF_UP, 0);
    struct ifreq req = {};
    snprintf(req.ifr_name, IFNAMSIZ, "lo");
    ASSERT_THAT(ioctl(fd(), SIOCGIFADDR, &req), SyscallSucceeds());
    EXPECT_EQ(
        reinterpret_cast<struct sockaddr_in*>(&req.ifr_addr)->sin_addr.s_addr,
        htonl(INADDR_LOOPBACK));
  }
}

// Attribute changes are reported even if a later attribute fails and the
// requested flags are unchanged.
TEST_F(NetdeviceNamespaceTest, PartialLinkChangeNotifiesSubscribers) {
  SetFlags(fd(), IFF_UP);
  const int old_mtu = MTU();
  struct sockaddr_nl address = {};
  address.nl_family = AF_NETLINK;
  address.nl_groups = RTMGRP_LINK;
  FileDescriptor observer =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE, &address));
  EXPECT_THAT(
      ChangeLink(IFF_UP, IFF_UP, {{IFLA_MTU, 1500}, {IFLA_MASTER, 0x7fffffff}}),
      PosixErrorIs(IsRunningOnGvisor() ? ENODEV : EINVAL, ::testing::_));
  EXPECT_NE(MTU(), old_mtu);
  struct pollfd ready = {};
  ready.fd = observer.get();
  ready.events = POLLIN;
  ASSERT_THAT(RetryEINTR(poll)(&ready, 1, 2000), SyscallSucceedsWithValue(1));
  alignas(struct nlmsghdr) char buffer[4096];
  ssize_t size =
      RetryEINTR(recv)(observer.get(), buffer, sizeof(buffer), MSG_DONTWAIT);
  ASSERT_GT(size, 0);
  bool found = false;
  for (auto* header = reinterpret_cast<struct nlmsghdr*>(buffer);
       NLMSG_OK(header, size); header = NLMSG_NEXT(header, size)) {
    if (header->nlmsg_type != RTM_NEWLINK ||
        header->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
      continue;
    }
    const auto* info =
        reinterpret_cast<const struct ifinfomsg*>(NLMSG_DATA(header));
    if ((info->ifi_flags & (IFF_UP | IFF_LOOPBACK)) ==
        (IFF_UP | IFF_LOOPBACK)) {
      found = true;
    }
  }
  EXPECT_TRUE(found);
}

// Missing devices and bad pointers fail without changing loopback state.
TEST_F(NetdeviceNamespaceTest, InvalidDeviceAndPointer) {
  struct ifreq req = {};
  snprintf(req.ifr_name, IFNAMSIZ, "missing");
  req.ifr_flags = IFF_UP;
  EXPECT_THAT(ioctl(fd(), SIOCSIFFLAGS, &req), SyscallFailsWithErrno(ENODEV));
  EXPECT_THAT(ioctl(fd(), SIOCSIFFLAGS, nullptr),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_EQ(Flags(fd()) & IFF_UP, 0);
}

// NET_ADMIN is required even when the named device does not exist.
TEST_F(NetdeviceNamespaceTest, RequiresNetAdmin) {
  AutoCapability no_net_admin(CAP_NET_ADMIN, false);
  struct ifreq req = {};
  snprintf(req.ifr_name, IFNAMSIZ, "lo");
  req.ifr_flags = IFF_UP;
  EXPECT_THAT(ioctl(fd(), SIOCSIFFLAGS, &req), SyscallFailsWithErrno(EPERM));
  snprintf(req.ifr_name, IFNAMSIZ, "missing");
  EXPECT_THAT(ioctl(fd(), SIOCSIFFLAGS, &req), SyscallFailsWithErrno(EPERM));
  EXPECT_EQ(Flags(fd()) & IFF_UP, 0);
}

// Old sockets keep querying and modifying their original network namespace.
TEST_F(NetdeviceNamespaceTest, SocketNamespaceSurvivesUnshare) {
  SetFlags(fd(), IFF_UP);
  ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceeds());
  FileDescriptor inner =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  EXPECT_EQ(Flags(fd()) & IFF_UP, IFF_UP);
  EXPECT_EQ(Flags(inner.get()) & IFF_UP, 0);
  SetFlags(fd(), 0);
  SetFlags(fd(), IFF_UP);
  EXPECT_EQ(Flags(inner.get()) & IFF_UP, 0);
  SetFlags(inner.get(), IFF_UP);
  EXPECT_EQ(Flags(inner.get()) & IFF_UP, IFF_UP);
}

// IPv6 and Unix sockets expose the same network-device ioctl interface.
TEST_F(NetdeviceNamespaceTest, OtherSocketFamilies) {
  FileDescriptor ipv6 =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_DGRAM, 0));
  SetFlags(ipv6.get(), IFF_UP);
  EXPECT_EQ(Flags(fd()) & IFF_UP, IFF_UP);
  FileDescriptor unix_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_DGRAM, 0));
  SetFlags(unix_socket.get(), 0);
  EXPECT_EQ(Flags(fd()) & IFF_UP, 0);
  SetFlags(unix_socket.get(), IFF_UP);
  EXPECT_EQ(Flags(fd()) & IFF_UP, IFF_UP);
}

TEST(NetdeviceTest, Loopback) {
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
  mask = htonl(mask);

  // Check that the loopback interface has the correct subnet mask.
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFNETMASK, &ifr), SyscallSucceeds());
  EXPECT_EQ(ifr.ifr_netmask.sa_family, AF_INET);
  struct sockaddr_in* sin =
      reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
  EXPECT_EQ(sin->sin_addr.s_addr, mask);
}

TEST(NetdeviceTest, InterfaceName) {
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
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  // Prepare the request.
  struct ifreq ifr = {};
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");

  // Check that SIOCGIFMTU returns a nonzero MTU.
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFMTU, &ifr), SyscallSucceeds());
  EXPECT_GT(ifr.ifr_mtu, 0);
}

TEST(NetdeviceTest, InterfaceQLEN) {
  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));

  // Prepare the request.
  struct ifreq ifr = {};
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");

  // Check that SIOCGIFTXQLEN returns without error.
  ASSERT_THAT(ioctl(sock.get(), SIOCGIFTXQLEN, &ifr), SyscallSucceeds());

  // Gvisor network doesn't implement queues and always returns 0.
  // When exposing the host network, lo could have any queue length set.
  if (IsRunningOnGvisor() && !IsRunningWithHostinet()) {
    EXPECT_EQ(ifr.ifr_qlen, 0);
  }
}

TEST(NetdeviceTest, EthtoolGetTSInfo) {
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
