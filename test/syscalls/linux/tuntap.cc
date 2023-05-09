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
#include <asm-generic/errno.h>
#include <linux/capability.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cstddef>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_split.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

constexpr int kIPLen = 4;

constexpr const char kDevNetTun[] = "/dev/net/tun";
constexpr const char kTapName[] = "tap0";
constexpr const char kTunName[] = "tun0";

#define kTapIPAddr htonl(0x0a000001)     /* Inet 10.0.0.1 */
#define kTapPeerIPAddr htonl(0x0a000002) /* Inet 10.0.0.2 */

constexpr const uint8_t kMacA[ETH_ALEN] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
constexpr const uint8_t kMacB[ETH_ALEN] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};

PosixErrorOr<std::set<std::string>> DumpLinkNames() {
  ASSIGN_OR_RETURN_ERRNO(auto links, DumpLinks());
  std::set<std::string> names;
  for (const auto& link : links) {
    names.emplace(link.name);
  }
  return names;
}

PosixErrorOr<Link> GetLinkByName(const std::string& name) {
  ASSIGN_OR_RETURN_ERRNO(auto links, DumpLinks());
  for (const auto& link : links) {
    if (link.name == name) {
      return link;
    }
  }
  return PosixError(ENOENT, "interface not found");
}

struct ping_ip_pkt {
  iphdr ip;
  icmphdr icmp;
  char payload[64];
} __attribute__((packed));

ping_ip_pkt CreatePingIPPacket(const in_addr_t srcip, const in_addr_t dstip) {
  ping_ip_pkt pkt = {};

  pkt.ip.ihl = 5;
  pkt.ip.version = 4;
  pkt.ip.tos = 0;
  pkt.ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) +
                         sizeof(pkt.payload));
  pkt.ip.id = 1;
  pkt.ip.frag_off = 1 << 6;  // Do not fragment
  pkt.ip.ttl = 64;
  pkt.ip.protocol = IPPROTO_ICMP;
  pkt.ip.daddr = dstip;
  pkt.ip.saddr = srcip;
  pkt.ip.check = IPChecksum(pkt.ip);

  pkt.icmp.type = ICMP_ECHO;
  pkt.icmp.code = 0;
  pkt.icmp.checksum = 0;
  pkt.icmp.un.echo.sequence = 1;
  pkt.icmp.un.echo.id = 1;

  strncpy(pkt.payload, "abcd", sizeof(pkt.payload));
  pkt.icmp.checksum = ICMPChecksum(pkt.icmp, pkt.payload, sizeof(pkt.payload));

  return pkt;
}

struct pihdr {
  uint16_t pi_flags;
  uint16_t pi_protocol;
} __attribute__((packed));

struct ping_pkt {
  pihdr pi;
  ethhdr eth;
  ping_ip_pkt ip_pkt;
} __attribute__((packed));

ping_pkt CreatePingPacket(const uint8_t srcmac[ETH_ALEN], const in_addr_t srcip,
                          const uint8_t dstmac[ETH_ALEN],
                          const in_addr_t dstip) {
  ping_pkt pkt = {};

  pkt.pi.pi_protocol = htons(ETH_P_IP);

  memcpy(pkt.eth.h_dest, dstmac, sizeof(pkt.eth.h_dest));
  memcpy(pkt.eth.h_source, srcmac, sizeof(pkt.eth.h_source));
  pkt.eth.h_proto = htons(ETH_P_IP);

  pkt.ip_pkt = CreatePingIPPacket(srcip, dstip);

  return pkt;
}

struct arp_pkt {
  pihdr pi;
  struct ethhdr eth;
  struct arphdr arp;
  uint8_t arp_sha[ETH_ALEN];
  uint8_t arp_spa[kIPLen];
  uint8_t arp_tha[ETH_ALEN];
  uint8_t arp_tpa[kIPLen];
} __attribute__((packed));

std::string CreateArpPacket(const uint8_t srcmac[ETH_ALEN],
                            const in_addr_t srcip,
                            const uint8_t dstmac[ETH_ALEN],
                            const in_addr_t dstip) {
  std::string buffer;
  buffer.resize(sizeof(arp_pkt));

  arp_pkt* pkt = reinterpret_cast<arp_pkt*>(&buffer[0]);
  {
    pkt->pi.pi_protocol = htons(ETH_P_ARP);

    memcpy(pkt->eth.h_dest, kMacA, sizeof(pkt->eth.h_dest));
    memcpy(pkt->eth.h_source, kMacB, sizeof(pkt->eth.h_source));
    pkt->eth.h_proto = htons(ETH_P_ARP);

    pkt->arp.ar_hrd = htons(ARPHRD_ETHER);
    pkt->arp.ar_pro = htons(ETH_P_IP);
    pkt->arp.ar_hln = ETH_ALEN;
    pkt->arp.ar_pln = kIPLen;
    pkt->arp.ar_op = htons(ARPOP_REPLY);

    memcpy(pkt->arp_sha, srcmac, sizeof(pkt->arp_sha));
    memcpy(pkt->arp_spa, &srcip, sizeof(pkt->arp_spa));
    memcpy(pkt->arp_tha, dstmac, sizeof(pkt->arp_tha));
    memcpy(pkt->arp_tpa, &dstip, sizeof(pkt->arp_tpa));
  }
  return buffer;
}

}  // namespace

TEST(TuntapStaticTest, NetTunExists) {
  struct stat statbuf;
  ASSERT_THAT(stat(kDevNetTun, &statbuf), SyscallSucceeds());
  // Check that it's a character device with rw-rw-rw- permissions.
  EXPECT_EQ(statbuf.st_mode, S_IFCHR | 0666);
}

class TuntapTest : public ::testing::Test {
 protected:
  void SetUp() override {
    const bool have_net_admin_cap =
        ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN));

    if (have_net_admin_cap && !IsRunningOnGvisor()) {
      // gVisor always creates enabled/up'd interfaces, while Linux does not (as
      // observed in b/110961832). Some of the tests require the Linux stack to
      // notify the socket of any link-address-resolution failures. Those
      // notifications do not seem to show up when the loopback interface in the
      // namespace is down.
      auto link = ASSERT_NO_ERRNO_AND_VALUE(GetLinkByName("lo"));
      ASSERT_NO_ERRNO(LinkChangeFlags(link.index, IFF_UP, IFF_UP));
    }
  }
};

TEST_F(TuntapTest, CreateInterfaceNoCap) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  AutoCapability cap(CAP_NET_ADMIN, false);

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(kDevNetTun, O_RDWR));

  struct ifreq ifr = {};
  ifr.ifr_flags = IFF_TAP;
  strncpy(ifr.ifr_name, kTapName, IFNAMSIZ);

  EXPECT_THAT(ioctl(fd.get(), TUNSETIFF, &ifr), SyscallFailsWithErrno(EPERM));
}

TEST_F(TuntapTest, CreateFixedNameInterface) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(kDevNetTun, O_RDWR));

  struct ifreq ifr_set = {};
  ifr_set.ifr_flags = IFF_TAP;
  strncpy(ifr_set.ifr_name, kTapName, IFNAMSIZ);
  EXPECT_THAT(ioctl(fd.get(), TUNSETIFF, &ifr_set),
              SyscallSucceedsWithValue(0));

  struct ifreq ifr_get = {};
  EXPECT_THAT(ioctl(fd.get(), TUNGETIFF, &ifr_get),
              SyscallSucceedsWithValue(0));

  struct ifreq ifr_expect = ifr_set;
  // See __tun_chr_ioctl() in net/drivers/tun.c.
  ifr_expect.ifr_flags |= IFF_NOFILTER;

  EXPECT_THAT(DumpLinkNames(),
              IsPosixErrorOkAndHolds(::testing::Contains(kTapName)));
  EXPECT_THAT(memcmp(&ifr_expect, &ifr_get, sizeof(ifr_get)), ::testing::Eq(0));
}

TEST_F(TuntapTest, CreateInterface) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(kDevNetTun, O_RDWR));

  struct ifreq ifr = {};
  ifr.ifr_flags = IFF_TAP;
  // Empty ifr.ifr_name. Let kernel assign.

  EXPECT_THAT(ioctl(fd.get(), TUNSETIFF, &ifr), SyscallSucceedsWithValue(0));

  struct ifreq ifr_get = {};
  EXPECT_THAT(ioctl(fd.get(), TUNGETIFF, &ifr_get),
              SyscallSucceedsWithValue(0));

  std::string ifname = ifr_get.ifr_name;
  EXPECT_THAT(ifname, ::testing::StartsWith("tap"));
  EXPECT_THAT(DumpLinkNames(),
              IsPosixErrorOkAndHolds(::testing::Contains(ifname)));
}

TEST_F(TuntapTest, InvalidReadWrite) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(kDevNetTun, O_RDWR));

  char buf[128] = {};
  EXPECT_THAT(read(fd.get(), buf, sizeof(buf)), SyscallFailsWithErrno(EBADFD));
  EXPECT_THAT(write(fd.get(), buf, sizeof(buf)), SyscallFailsWithErrno(EBADFD));
}

TEST_F(TuntapTest, ZeroWrite) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(kDevNetTun, O_RDWR));
  struct ifreq ifr_set = {};
  ifr_set.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr_set.ifr_name, kTunName, IFNAMSIZ);
  EXPECT_THAT(ioctl(fd.get(), TUNSETIFF, &ifr_set), SyscallSucceeds());
  EXPECT_THAT(write(fd.get(), nullptr, 0), SyscallFailsWithErrno(EINVAL));
}

TEST_F(TuntapTest, WriteToDownDevice) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // FIXME(b/110961832): gVisor always creates enabled/up'd interfaces.
  SKIP_IF(IsRunningOnGvisor());

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(kDevNetTun, O_RDWR));

  // Device created should be down by default.
  struct ifreq ifr = {};
  ifr.ifr_flags = IFF_TAP;
  EXPECT_THAT(ioctl(fd.get(), TUNSETIFF, &ifr), SyscallSucceedsWithValue(0));

  char buf[128] = {};
  EXPECT_THAT(write(fd.get(), buf, sizeof(buf)), SyscallFailsWithErrno(EIO));
}

struct TunTapInterface {
  FileDescriptor fd;
  Link link;
};

PosixErrorOr<TunTapInterface> OpenAndAttachTunTap(const std::string& dev_name,
                                                  const in_addr_t dev_addr,
                                                  bool tap, bool no_pi) {
  // Interface creation.
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, Open(kDevNetTun, O_RDWR));

  struct ifreq ifr_set = {};
  if (tap) {
    ifr_set.ifr_flags |= IFF_TAP;
  } else {
    ifr_set.ifr_flags |= IFF_TUN;
  }
  if (no_pi) {
    ifr_set.ifr_flags |= IFF_NO_PI;
  }
  strncpy(ifr_set.ifr_name, dev_name.c_str(), IFNAMSIZ);
  if (ioctl(fd.get(), TUNSETIFF, &ifr_set) < 0) {
    return PosixError(errno);
  }

  ASSIGN_OR_RETURN_ERRNO(auto link, GetLinkByName(dev_name));

  const struct in_addr dev_ipv4_addr = {.s_addr = dev_addr};
  // Interface setup.
  EXPECT_NO_ERRNO(LinkAddLocalAddr(link.index, AF_INET, /*prefixlen=*/24,
                                   &dev_ipv4_addr, sizeof(dev_ipv4_addr)));

  if (!IsRunningOnGvisor()) {
    // FIXME(b/110961832): gVisor doesn't support setting MAC address on
    // interfaces yet.
    if (tap) {
      RETURN_IF_ERRNO(LinkSetMacAddr(link.index, kMacA, sizeof(kMacA)));
    }

    // FIXME(b/110961832): gVisor always creates enabled/up'd interfaces.
    RETURN_IF_ERRNO(LinkChangeFlags(link.index, IFF_UP, IFF_UP));
  }

  return TunTapInterface{.fd = std::move(fd), .link = std::move(link)};
}

// This test sets up a TAP device and pings kernel by sending ICMP echo request.
//
// It works as the following:
// * Open /dev/net/tun, and create kTapName interface.
// * Use rtnetlink to do initial setup of the interface:
//   * Assign IP address 10.0.0.1/24 to kernel.
//   * MAC address: kMacA
//   * Bring up the interface.
// * Send an ICMP echo reqest (ping) packet from 10.0.0.2 (kMacB) to kernel.
// * Loop to receive packets from TAP device/fd:
//   * If packet is an ICMP echo reply, it stops and passes the test.
//   * If packet is an ARP request, it responds with canned reply and resends
//   the
//     ICMP request packet.
TEST_F(TuntapTest, PingKernel) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  const auto& [fd, link] = ASSERT_NO_ERRNO_AND_VALUE(OpenAndAttachTunTap(
      kTapName, kTapIPAddr, true /* tap */, false /* no_pi */));

  ping_pkt ping_req =
      CreatePingPacket(kMacB, kTapPeerIPAddr, kMacA, kTapIPAddr);
  std::string arp_rep =
      CreateArpPacket(kMacB, kTapPeerIPAddr, kMacA, kTapIPAddr);

  // Send ping, this would trigger an ARP request on Linux.
  EXPECT_THAT(write(fd.get(), &ping_req, sizeof(ping_req)),
              SyscallSucceedsWithValue(sizeof(ping_req)));

  // Receive loop to process inbound packets.
  struct inpkt {
    union {
      pihdr pi;
      ping_pkt ping;
      arp_pkt arp;
    };
  };
  while (1) {
    inpkt r = {};
    size_t n;
    EXPECT_THAT(n = read(fd.get(), &r, sizeof(r)), SyscallSucceeds());

    if (n < sizeof(pihdr)) {
      std::cerr << "Ignored packet, protocol: " << r.pi.pi_protocol
                << " len: " << n << std::endl;
      continue;
    }

    // Process ARP packet.
    if (n >= sizeof(arp_pkt) && r.pi.pi_protocol == htons(ETH_P_ARP)) {
      // Respond with canned ARP reply.
      EXPECT_THAT(write(fd.get(), arp_rep.data(), arp_rep.size()),
                  SyscallSucceedsWithValue(arp_rep.size()));
      // First ping request might have been dropped due to mac address not in
      // ARP cache. Send it again.
      EXPECT_THAT(write(fd.get(), &ping_req, sizeof(ping_req)),
                  SyscallSucceedsWithValue(sizeof(ping_req)));
    }

    // Process ping response packet.
    if (n >= sizeof(ping_pkt) && r.pi.pi_protocol == ping_req.pi.pi_protocol &&
        r.ping.ip_pkt.ip.protocol == ping_req.ip_pkt.ip.protocol &&
        !memcmp(&r.ping.ip_pkt.ip.saddr, &ping_req.ip_pkt.ip.daddr, kIPLen) &&
        !memcmp(&r.ping.ip_pkt.ip.daddr, &ping_req.ip_pkt.ip.saddr, kIPLen) &&
        r.ping.ip_pkt.icmp.type == 0 && r.ping.ip_pkt.icmp.code == 0) {
      // Ends and passes the test.
      break;
    }
  }
}

TEST_F(TuntapTest, LargeWritesFailWithEMSGSIZE) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  const auto& [fd, link] = ASSERT_NO_ERRNO_AND_VALUE(OpenAndAttachTunTap(
      kTapName, kTapIPAddr, true /* tap */, false /* no_pi */));

  ping_pkt ping_req =
      CreatePingPacket(kMacB, kTapPeerIPAddr, kMacA, kTapIPAddr);
  std::string arp_rep =
      CreateArpPacket(kMacB, kTapPeerIPAddr, kMacA, kTapIPAddr);

  constexpr int kBufSize = 4096;
  std::vector<char> buf(kBufSize);
  struct iovec iov[2] = {
      {
          .iov_base = &ping_req,
          .iov_len = sizeof(ping_req),
      },
      {
          .iov_base = buf.data(),
          .iov_len = kBufSize,
      },
  };

  // A packet is large than MTU which is 1500 by default..
  EXPECT_THAT(writev(fd.get(), iov, 2), SyscallFailsWithErrno(EMSGSIZE));
}

TEST_F(TuntapTest, SendUdpTriggersArpResolution) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  const auto& [fd, link] = ASSERT_NO_ERRNO_AND_VALUE(OpenAndAttachTunTap(
      kTapName, kTapIPAddr, true /* tap */, false /* no_pi */));

  // Send a UDP packet to remote.
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  ASSERT_THAT(sock, SyscallSucceeds());

  struct sockaddr_in remote = {
      .sin_family = AF_INET,
      .sin_port = htons(42),
      .sin_addr = {.s_addr = kTapPeerIPAddr},
  };
  ASSERT_THAT(sendto(sock, "hello", 5, 0, AsSockAddr(&remote), sizeof(remote)),
              SyscallSucceeds());

  struct inpkt {
    union {
      pihdr pi;
      arp_pkt arp;
    };
  };
  while (1) {
    inpkt r = {};
    size_t n;
    EXPECT_THAT(n = read(fd.get(), &r, sizeof(r)), SyscallSucceeds());

    if (n < sizeof(pihdr)) {
      std::cerr << "Ignored packet, protocol: " << r.pi.pi_protocol
                << " len: " << n << std::endl;
      continue;
    }

    if (n >= sizeof(arp_pkt) && r.pi.pi_protocol == htons(ETH_P_ARP)) {
      break;
    }
  }
}

TEST_F(TuntapTest, TUNNoPacketInfo) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  // Interface creation.
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(kDevNetTun, O_RDWR));

  struct ifreq ifr_set = {};
  ifr_set.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr_set.ifr_name, kTunName, IFNAMSIZ);
  EXPECT_THAT(ioctl(fd.get(), TUNSETIFF, &ifr_set), SyscallSucceeds());

  // Interface setup.
  auto link = ASSERT_NO_ERRNO_AND_VALUE(GetLinkByName(kTunName));
  const struct in_addr dev_ipv4_addr = {.s_addr = kTapIPAddr};
  EXPECT_NO_ERRNO(LinkAddLocalAddr(link.index, AF_INET, 24, &dev_ipv4_addr,
                                   sizeof(dev_ipv4_addr)));

  ping_ip_pkt ping_req = CreatePingIPPacket(kTapPeerIPAddr, kTapIPAddr);

  // Send ICMP query
  EXPECT_THAT(write(fd.get(), &ping_req, sizeof(ping_req)),
              SyscallSucceedsWithValue(sizeof(ping_req)));

  // Receive loop to process inbound packets.
  while (1) {
    ping_ip_pkt ping_resp = {};
    EXPECT_THAT(read(fd.get(), &ping_resp, sizeof(ping_req)),
                SyscallSucceedsWithValue(sizeof(ping_req)));

    // Process ping response packet.
    if (!memcmp(&ping_resp.ip.saddr, &ping_req.ip.daddr, kIPLen) &&
        !memcmp(&ping_resp.ip.daddr, &ping_req.ip.saddr, kIPLen) &&
        ping_resp.icmp.type == 0 && ping_resp.icmp.code == 0) {
      // Ends and passes the test.
      break;
    }
  }
}

// TCPBlockingConnectFailsArpResolution tests for TCP connect to fail on link
// address resolution failure to a routable, but non existent peer.
TEST_F(TuntapTest, TCPBlockingConnectFailsArpResolution) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  FileDescriptor sender =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));

  const auto tuntap = ASSERT_NO_ERRNO_AND_VALUE(OpenAndAttachTunTap(
      kTapName, kTapIPAddr, true /* tap */, false /* no_pi */));

  sockaddr_in connect_addr = {
      .sin_family = AF_INET,
      .sin_addr = {.s_addr = kTapPeerIPAddr},
  };
  ASSERT_THAT(connect(sender.get(),
                      reinterpret_cast<const struct sockaddr*>(&connect_addr),
                      sizeof(connect_addr)),
              SyscallFailsWithErrno(EHOSTUNREACH));
}

// TCPNonBlockingConnectFailsArpResolution tests for TCP non-blocking connect to
// to trigger an error event to be notified to poll on link address resolution
// failure to a routable, but non existent peer.
TEST_F(TuntapTest, TCPNonBlockingConnectFailsArpResolution) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  FileDescriptor sender = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP));

  const auto tuntap = ASSERT_NO_ERRNO_AND_VALUE(OpenAndAttachTunTap(
      kTapName, kTapIPAddr, true /* tap */, false /* no_pi */));

  sockaddr_in connect_addr = {
      .sin_family = AF_INET,
      .sin_addr = {.s_addr = kTapPeerIPAddr},
  };
  ASSERT_THAT(connect(sender.get(),
                      reinterpret_cast<const struct sockaddr*>(&connect_addr),
                      sizeof(connect_addr)),
              SyscallFailsWithErrno(EINPROGRESS));

  constexpr int kTimeout = 10000;
  struct pollfd pfd = {
      .fd = sender.get(),
      .events = POLLIN | POLLOUT,
  };
  ASSERT_THAT(poll(&pfd, 1, kTimeout), SyscallSucceedsWithValue(1));
  ASSERT_EQ(pfd.revents, POLLIN | POLLOUT | POLLHUP | POLLERR);

  ASSERT_THAT(connect(sender.get(),
                      reinterpret_cast<const struct sockaddr*>(&connect_addr),
                      sizeof(connect_addr)),
              SyscallFailsWithErrno(EHOSTUNREACH));
}

// Write hang bug found by syskaller: b/155928773
// https://syzkaller.appspot.com/bug?id=065b893bd8d1d04a4e0a1d53c578537cde1efe99
TEST_F(TuntapTest, WriteHangBug155928773) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));

  const auto tuntap = ASSERT_NO_ERRNO_AND_VALUE(OpenAndAttachTunTap(
      kTapName, kTapIPAddr, true /* tap */, false /* no_pi */));

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_THAT(sock, SyscallSucceeds());

  struct sockaddr_in remote = {
      .sin_family = AF_INET,
      .sin_port = htons(42),
      .sin_addr = {.s_addr = kTapIPAddr},
  };
  // Return values do not matter in this test.
  connect(sock, AsSockAddr(&remote), sizeof(remote));
  write(sock, "hello", 5);
}

// Test that raw packet sockets do not need/include link headers when
// sending/receiving packets to/from pure L3 (e.g. TUN) interfaces.
TEST_F(TuntapTest, RawPacketSocket) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  auto [tun, link] = ASSERT_NO_ERRNO_AND_VALUE(OpenAndAttachTunTap(
      kTunName, kTapIPAddr, false /* tap */, true /* no_pi */));
  FileDescriptor packet_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)));

  constexpr int kInfiniteTimeout = -1;

  uint8_t hardware_address_length = 0;
  if (IsRunningOnGvisor()) {
    // TODO(https://gvisor.dev/issue/6530): Do not assume all interfaces have
    // an ethernet address.
    hardware_address_length = ETH_ALEN;
  }

  {
    const ping_ip_pkt ping_req = CreatePingIPPacket(kTapPeerIPAddr, kTapIPAddr);
    ASSERT_THAT(write(tun.get(), &ping_req, sizeof(ping_req)),
                SyscallSucceedsWithValue(sizeof(ping_req)));
    // Wait for the packet socket to become readable.
    pollfd pfd = {
        .fd = packet_sock.get(),
        .events = POLLIN,
    };
    ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, kInfiniteTimeout),
                SyscallSucceedsWithValue(1));

    char read_buf[sizeof(ping_req) + 1];
    struct sockaddr_ll src;
    socklen_t src_len = sizeof(src);
    ASSERT_THAT(recvfrom(packet_sock.get(), read_buf, sizeof(read_buf), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &src_len),
                SyscallSucceedsWithValue(sizeof(ping_req)));
    EXPECT_EQ(memcmp(read_buf, &ping_req, sizeof(ping_req)), 0);
    ASSERT_EQ(src_len, sizeof(src));
    EXPECT_EQ(src.sll_family, AF_PACKET);
    EXPECT_EQ(ntohs(src.sll_protocol), ETH_P_IP);
    EXPECT_EQ(src.sll_ifindex, link.index);
    EXPECT_EQ(src.sll_pkttype, PACKET_HOST);
    EXPECT_EQ(src.sll_halen, hardware_address_length);
    if (IsRunningOnGvisor()) {
      // TODO(https://gvisor.dev/issue/6531): Check this field for the right
      // hardware type.
      EXPECT_EQ(src.sll_hatype, 0);
    } else {
      EXPECT_EQ(src.sll_hatype, ARPHRD_NONE);
    }
  }

  {
    const struct sockaddr_ll dest = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex = link.index,
        .sll_halen = hardware_address_length,
    };

    const ping_ip_pkt ping_req = CreatePingIPPacket(kTapIPAddr, kTapPeerIPAddr);
    ASSERT_THAT(
        sendto(packet_sock.get(), &ping_req, sizeof(ping_req), 0,
               reinterpret_cast<const struct sockaddr*>(&dest), sizeof(dest)),
        SyscallSucceedsWithValue(sizeof(ping_req)));

    // Loop until we receive the packet we expect - the kernel may send packets
    // we do not care about.
    while (true) {
      // Wait for the TUN interface to become readable.
      pollfd pfd = {
          .fd = tun.get(),
          .events = POLLIN,
      };
      ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, kInfiniteTimeout),
                  SyscallSucceedsWithValue(1));

      char read_buf[sizeof(ping_req) + 1];
      int n = read(tun.get(), &read_buf, sizeof(read_buf));
      ASSERT_THAT(n, SyscallSucceeds());
      if (n == sizeof(ping_req) &&
          memcmp(read_buf, &ping_req, sizeof(ping_req)) == 0) {
        break;
      }
    }
  }
}

}  // namespace testing
}  // namespace gvisor
