// Copyright 2026 The gVisor Authors.
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
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Linux network headers require <net/if.h> and <netinet/in.h> to precede them.
// clang-format off
#include <net/if.h>
#include <netinet/in.h>
// clang-format on

#include <linux/capability.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/veth.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

using MacAddress = std::array<uint8_t, ETH_ALEN>;

constexpr uint32_t kSeq = 7000;
constexpr uint16_t kPort = 9000;
constexpr char kBridgeIP[] = "192.0.2.1";
constexpr char kPeerIP[] = "192.0.2.2";
constexpr MacAddress kBridgeMac = {0x02, 0x00, 0x00, 0x00, 0xb0, 0x01};
constexpr MacAddress kUnknownMac = {0x02, 0x00, 0x00, 0x00, 0xb0, 0x02};
constexpr MacAddress kNewPortAMac = {0x02, 0x00, 0x00, 0x00, 0xb0, 0x03};
constexpr MacAddress kNewPortBMac = {0x02, 0x00, 0x00, 0x00, 0xb0, 0x04};
constexpr MacAddress kBroadcastMac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
constexpr size_t kPayloadOffset =
    sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

struct LinkRequest {
  struct nlmsghdr hdr;
  struct ifinfomsg ifm;
  char buf[512];
};

struct rtattr* AddAttr(LinkRequest* req, int type, const void* data, int len) {
  struct rtattr* rta = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<char*>(req) + NLMSG_ALIGN(req->hdr.nlmsg_len));
  TEST_CHECK(NLMSG_ALIGN(req->hdr.nlmsg_len) + RTA_SPACE(len) <= sizeof(*req));
  rta->rta_type = type;
  rta->rta_len = RTA_LENGTH(len);
  if (len > 0) {
    memcpy(RTA_DATA(rta), data, len);
  }
  req->hdr.nlmsg_len = NLMSG_ALIGN(req->hdr.nlmsg_len) + RTA_SPACE(len);
  return rta;
}

void EndNest(LinkRequest* req, struct rtattr* nest) {
  nest->rta_len = reinterpret_cast<char*>(req) + req->hdr.nlmsg_len -
                  reinterpret_cast<char*>(nest);
}

// Creates a link of the given kind. If peer is not null, the link is a veth
// pair and peer names the other end.
PosixError NewLink(const FileDescriptor& fd, uint32_t seq, const char* kind,
                   const char* name, const char* peer) {
  LinkRequest req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifm));
  req.hdr.nlmsg_type = RTM_NEWLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
  req.hdr.nlmsg_seq = seq;
  AddAttr(&req, IFLA_IFNAME, name, strlen(name));
  struct rtattr* linkinfo = AddAttr(&req, IFLA_LINKINFO, nullptr, 0);
  AddAttr(&req, IFLA_INFO_KIND, kind, strlen(kind));
  if (peer != nullptr) {
    struct rtattr* data = AddAttr(&req, IFLA_INFO_DATA, nullptr, 0);
    struct ifinfomsg peer_ifm = {};
    struct rtattr* peer_info =
        AddAttr(&req, VETH_INFO_PEER, &peer_ifm, sizeof(peer_ifm));
    AddAttr(&req, IFLA_IFNAME, peer, strlen(peer));
    EndNest(&req, peer_info);
    EndNest(&req, data);
  }
  EndNest(&req, linkinfo);
  return NetlinkRequestAckOrError(fd, seq, &req, req.hdr.nlmsg_len);
}

// Sets one attribute of an existing link.
PosixError SetLinkAttr(const FileDescriptor& fd, uint32_t seq, int index,
                       int type, const void* data, int len) {
  LinkRequest req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifm));
  req.hdr.nlmsg_type = RTM_NEWLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.hdr.nlmsg_seq = seq;
  req.ifm.ifi_index = index;
  AddAttr(&req, type, data, len);
  return NetlinkRequestAckOrError(fd, seq, &req, req.hdr.nlmsg_len);
}

// Creates the bridge name if index is 0, or changes the bridge with that
// index otherwise, with the bridge attribute type set to data.
PosixError SetBridgeAttr(const FileDescriptor& fd, uint32_t seq, int index,
                         const char* name, int type, const void* data,
                         int len) {
  LinkRequest req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifm));
  req.hdr.nlmsg_type = RTM_NEWLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.hdr.nlmsg_seq = seq;
  if (index == 0) {
    req.hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    AddAttr(&req, IFLA_IFNAME, name, strlen(name));
  }
  req.ifm.ifi_index = index;
  struct rtattr* linkinfo = AddAttr(&req, IFLA_LINKINFO, nullptr, 0);
  AddAttr(&req, IFLA_INFO_KIND, "bridge", strlen("bridge"));
  struct rtattr* data_attr = AddAttr(&req, IFLA_INFO_DATA, nullptr, 0);
  AddAttr(&req, type, data, len);
  EndNest(&req, data_attr);
  EndNest(&req, linkinfo);
  return NetlinkRequestAckOrError(fd, seq, &req, req.hdr.nlmsg_len);
}

PosixErrorOr<MacAddress> HardwareAddress(const char* name) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor s, Socket(AF_INET, SOCK_DGRAM, 0));
  struct ifreq ifr = {};
  strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
  RETURN_ERROR_IF_SYSCALL_FAIL(ioctl(s.get(), SIOCGIFHWADDR, &ifr));
  MacAddress mac;
  memcpy(mac.data(), ifr.ifr_hwaddr.sa_data, mac.size());
  return mac;
}

// The bridge br0 has ports pA and pB, the ends of veth pairs whose other ends
// oA and oB are outside the bridge. Frames are injected at oA, so they enter
// the bridge at pA. A UDP socket on br0's address shows whether a frame was
// passed up and accepted by br0's IP layer, and a packet socket on oB shows
// whether the bridge sent it out of pB.
class BridgeLocalDeliveryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
    SKIP_IF(IsRunningWithHostinet());

    netns_ =
        ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/net", O_RDONLY));
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceeds());

    FileDescriptor nl =
        ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
    PosixError err = NewLink(nl, kSeq, "bridge", "br0", nullptr);
    // Native Linux kernels may not be built with CONFIG_BRIDGE.
    SKIP_IF(!IsRunningOnGvisor() && err.errno_value() == EOPNOTSUPP);
    ASSERT_NO_ERRNO(err);
    ASSERT_NO_ERRNO(NewLink(nl, kSeq + 1, "veth", "pA", "oA"));
    ASSERT_NO_ERRNO(NewLink(nl, kSeq + 2, "veth", "pB", "oB"));

    const int br = if_nametoindex("br0");
    ASSERT_NE(br, 0);
    const int port_a = if_nametoindex("pA");
    ASSERT_NE(port_a, 0);
    const int port_b = if_nametoindex("pB");
    ASSERT_NE(port_b, 0);
    out_a_ = if_nametoindex("oA");
    ASSERT_NE(out_a_, 0);
    const int out_b = if_nametoindex("oB");
    ASSERT_NE(out_b, 0);

    // Linux gives a bridge without an explicit address the lowest port
    // address, which would make it indistinguishable from a port's.
    ASSERT_NO_ERRNO(SetLinkAttr(nl, kSeq + 3, br, IFLA_ADDRESS,
                                kBridgeMac.data(), kBridgeMac.size()));
    uint32_t seq = kSeq + 4;
    for (int port : {port_a, port_b}) {
      ASSERT_NO_ERRNO(
          SetLinkAttr(nl, seq++, port, IFLA_MASTER, &br, sizeof(br)));
    }
    for (int index : {br, port_a, port_b, out_a_, out_b}) {
      ASSERT_NO_ERRNO(LinkChangeFlags(index, IFF_UP, IFF_UP));
    }
    struct in_addr addr;
    ASSERT_EQ(inet_pton(AF_INET, kBridgeIP, &addr), 1);
    ASSERT_NO_ERRNO(LinkAddLocalAddr(nl, br, AF_INET, 24, &addr, sizeof(addr)));

    bridge_mac_ = ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("br0"));
    port_a_mac_ = ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("pA"));
    port_b_mac_ = ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("pB"));
    out_a_mac_ = ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("oA"));
    ASSERT_EQ(bridge_mac_, kBridgeMac);
    ASSERT_NE(port_a_mac_, port_b_mac_);
    for (const MacAddress& mac : {bridge_mac_, port_a_mac_, port_b_mac_}) {
      ASSERT_NE(mac, kUnknownMac);
      ASSERT_NE(mac, kNewPortAMac);
      ASSERT_NE(mac, kNewPortBMac);
    }

    sender_ = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_RAW, 0));

    udp_ = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
    struct sockaddr_in bind_addr = {};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(kPort);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ASSERT_THAT(bind(udp_.get(), reinterpret_cast<sockaddr*>(&bind_addr),
                     sizeof(bind_addr)),
                SyscallSucceeds());

    port_b_out_ = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_IP)));
    struct sockaddr_ll ll = {};
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_IP);
    ll.sll_ifindex = out_b;
    ASSERT_THAT(
        bind(port_b_out_.get(), reinterpret_cast<sockaddr*>(&ll), sizeof(ll)),
        SyscallSucceeds());

    // Linux enables bridge ports asynchronously once their carrier is up.
    const absl::Time deadline = absl::Now() + absl::Seconds(10);
    bool ready = false;
    while (!ready && absl::Now() < deadline) {
      const std::string marker = NextMarker();
      ASSERT_NO_FATAL_FAILURE(SendFrame(kBroadcastMac, marker));
      bool unused, up, out;
      ASSERT_NO_FATAL_FAILURE(ReceiveUntil(
          udp_.get(), 0, "", marker, absl::Milliseconds(100), &unused, &up));
      ASSERT_NO_FATAL_FAILURE(ReceiveUntil(port_b_out_.get(), kPayloadOffset,
                                           "", marker, absl::Milliseconds(100),
                                           &unused, &out));
      ready = up && out;
    }
    ASSERT_TRUE(ready) << "bridge did not start forwarding";
  }

  void TearDown() override {
    if (netns_.get() >= 0) {
      EXPECT_THAT(setns(netns_.get(), CLONE_NEWNET), SyscallSucceeds());
    }
  }

  std::string NextMarker() {
    return "bridge-local-delivery-" + std::to_string(next_marker_++);
  }

  // Sends a UDP datagram for kBridgeIP:kPort carrying payload in an Ethernet
  // frame for dst out of oA.
  void SendFrame(const MacAddress& dst, const std::string& payload) {
    std::string frame(kPayloadOffset + payload.size(), '\0');
    struct ethhdr eth = {};
    memcpy(eth.h_dest, dst.data(), ETH_ALEN);
    memcpy(eth.h_source, out_a_mac_.data(), ETH_ALEN);
    eth.h_proto = htons(ETH_P_IP);

    struct iphdr ip = {};
    ip.version = 4;
    ip.ihl = sizeof(ip) / 4;
    ip.tot_len = htons(frame.size() - sizeof(eth));
    ip.ttl = 64;
    ip.protocol = IPPROTO_UDP;
    ASSERT_EQ(inet_pton(AF_INET, kPeerIP, &ip.saddr), 1);
    ASSERT_EQ(inet_pton(AF_INET, kBridgeIP, &ip.daddr), 1);
    ip.check = IPChecksum(ip);

    struct udphdr udp = {};
    udp.source = htons(kPort);
    udp.dest = htons(kPort);
    udp.len = htons(sizeof(udp) + payload.size());

    memcpy(&frame[0], &eth, sizeof(eth));
    memcpy(&frame[sizeof(eth)], &ip, sizeof(ip));
    memcpy(&frame[sizeof(eth) + sizeof(ip)], &udp, sizeof(udp));
    memcpy(&frame[kPayloadOffset], payload.data(), payload.size());

    struct sockaddr_ll ll = {};
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_IP);
    ll.sll_ifindex = out_a_;
    ll.sll_halen = ETH_ALEN;
    memcpy(ll.sll_addr, dst.data(), ETH_ALEN);
    ASSERT_THAT(sendto(sender_.get(), frame.data(), frame.size(), 0,
                       reinterpret_cast<sockaddr*>(&ll), sizeof(ll)),
                SyscallSucceedsWithValue(frame.size()));
  }

  // Reads the next incoming packet on fd, whose payload starts at offset, and
  // returns its payload, or returns an empty string if none arrives within
  // timeout.
  void NextPayload(int fd, size_t offset, absl::Duration timeout,
                   std::string* payload) {
    payload->clear();
    const absl::Time deadline = absl::Now() + timeout;
    while (payload->empty()) {
      const absl::Duration left = deadline - absl::Now();
      if (left <= absl::ZeroDuration()) {
        return;
      }
      struct pollfd pfd = {.fd = fd, .events = POLLIN};
      const int n = poll(&pfd, 1, absl::ToInt64Milliseconds(left) + 1);
      ASSERT_THAT(n, SyscallSucceeds());
      if (n == 0) {
        return;
      }
      char buf[2048];
      struct sockaddr_ll from = {};
      socklen_t from_len = sizeof(from);
      const ssize_t len =
          recvfrom(fd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from),
                   &from_len);
      if (len < 0 && errno == EAGAIN) {
        continue;
      }
      ASSERT_THAT(len, SyscallSucceeds());
      if (from.sll_family == AF_PACKET && from.sll_pkttype == PACKET_OUTGOING) {
        continue;
      }
      if (static_cast<size_t>(len) > offset) {
        payload->assign(buf + offset, len - offset);
      }
    }
  }

  // Reads from fd until a packet carrying until arrives or timeout passes, and
  // reports whether one carrying want arrived first.
  void ReceiveUntil(int fd, size_t offset, const std::string& want,
                    const std::string& until, absl::Duration timeout,
                    bool* seen_want, bool* seen_until) {
    *seen_want = false;
    *seen_until = false;
    const absl::Time deadline = absl::Now() + timeout;
    while (!*seen_until) {
      std::string payload;
      ASSERT_NO_FATAL_FAILURE(
          NextPayload(fd, offset, deadline - absl::Now(), &payload));
      if (payload.empty()) {
        return;
      }
      *seen_want |= payload == want;
      *seen_until = payload == until;
    }
  }

  // Sends a frame for dst from oA and reports whether it was delivered to the
  // UDP socket on br0 and whether it left the bridge through pB. A broadcast
  // sent after it, which reaches both, bounds how long to wait for it.
  void Deliver(const MacAddress& dst, bool* delivered, bool* forwarded) {
    const std::string marker = NextMarker();
    const std::string sentinel = NextMarker();
    ASSERT_NO_FATAL_FAILURE(SendFrame(dst, marker));
    ASSERT_NO_FATAL_FAILURE(SendFrame(kBroadcastMac, sentinel));
    ASSERT_NO_FATAL_FAILURE(Drain(udp_.get(), 0, marker, sentinel, delivered));
    ASSERT_NO_FATAL_FAILURE(
        Drain(port_b_out_.get(), kPayloadOffset, marker, sentinel, forwarded));
  }

  void Drain(int fd, size_t offset, const std::string& marker,
             const std::string& sentinel, bool* seen) {
    bool got_sentinel;
    ASSERT_NO_FATAL_FAILURE(ReceiveUntil(
        fd, offset, marker, sentinel, absl::Seconds(5), seen, &got_sentinel));
    ASSERT_TRUE(got_sentinel) << "broadcast " << sentinel << " not received";
    if (!*seen) {
      // Allow for the marker being reordered after the sentinel.
      bool unused;
      ASSERT_NO_FATAL_FAILURE(ReceiveUntil(fd, offset, sentinel, marker,
                                           absl::Milliseconds(200), &unused,
                                           seen));
    }
  }

  // Don't do cooperative save/restore because netstack state is not restored.
  // TODO(gvisor.dev/issue/4595): enable cooperative save tests.
  const DisableSave ds_;
  FileDescriptor netns_;
  FileDescriptor sender_;
  FileDescriptor udp_;
  FileDescriptor port_b_out_;
  int out_a_ = 0;
  MacAddress bridge_mac_;
  MacAddress port_a_mac_;
  MacAddress port_b_mac_;
  MacAddress out_a_mac_;
  int next_marker_ = 0;
};

// Linux: br_handle_frame_finish passes frames for a BR_FDB_LOCAL address up
// with br_pass_frame_up and does not forward them.
TEST_F(BridgeLocalDeliveryTest, BridgeAddressIsPassedUpNotForwarded) {
  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(bridge_mac_, &delivered, &forwarded));
  EXPECT_TRUE(delivered);
  EXPECT_FALSE(forwarded);
}

TEST_F(BridgeLocalDeliveryTest, IngressPortAddressIsPassedUpNotForwarded) {
  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(port_a_mac_, &delivered, &forwarded));
  EXPECT_TRUE(delivered);
  EXPECT_FALSE(forwarded);
}

TEST_F(BridgeLocalDeliveryTest, OtherPortAddressIsNotForwarded) {
  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(port_b_mac_, &delivered, &forwarded));
  // The frame is passed up as PACKET_OTHERHOST, which ip_rcv drops.
  EXPECT_FALSE(delivered);
  EXPECT_FALSE(forwarded);
}

TEST_F(BridgeLocalDeliveryTest, UnknownUnicastIsFloodedNotPassedUp) {
  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(kUnknownMac, &delivered, &forwarded));
  EXPECT_FALSE(delivered);
  EXPECT_TRUE(forwarded);
}

TEST_F(BridgeLocalDeliveryTest, BroadcastIsFloodedAndPassedUp) {
  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(kBroadcastMac, &delivered, &forwarded));
  EXPECT_TRUE(delivered);
  EXPECT_TRUE(forwarded);
}

// Linux: br_device_event calls br_fdb_changeaddr on NETDEV_CHANGEADDR, which
// replaces the port's BR_FDB_LOCAL entry.
TEST_F(BridgeLocalDeliveryTest, PortAddressChangeIsTracked) {
  FileDescriptor nl =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  const int port_a = if_nametoindex("pA");
  ASSERT_NE(port_a, 0);
  const int port_b = if_nametoindex("pB");
  ASSERT_NE(port_b, 0);
  ASSERT_NO_ERRNO(SetLinkAttr(nl, kSeq + 10, port_a, IFLA_ADDRESS,
                              kNewPortAMac.data(), kNewPortAMac.size()));
  ASSERT_NO_ERRNO(SetLinkAttr(nl, kSeq + 11, port_b, IFLA_ADDRESS,
                              kNewPortBMac.data(), kNewPortBMac.size()));
  ASSERT_EQ(ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("pA")), kNewPortAMac);
  ASSERT_EQ(ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("pB")), kNewPortBMac);

  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(kNewPortAMac, &delivered, &forwarded));
  EXPECT_TRUE(delivered) << "new ingress-port address";
  EXPECT_FALSE(forwarded) << "new ingress-port address";
  ASSERT_NO_FATAL_FAILURE(Deliver(kNewPortBMac, &delivered, &forwarded));
  EXPECT_FALSE(delivered) << "new other-port address";
  EXPECT_FALSE(forwarded) << "new other-port address";
  ASSERT_NO_FATAL_FAILURE(Deliver(port_a_mac_, &delivered, &forwarded));
  EXPECT_FALSE(delivered) << "old ingress-port address";
  EXPECT_TRUE(forwarded) << "old ingress-port address";
  ASSERT_NO_FATAL_FAILURE(Deliver(port_b_mac_, &delivered, &forwarded));
  EXPECT_FALSE(delivered) << "old other-port address";
  EXPECT_TRUE(forwarded) << "old other-port address";
}

// br0 is a bridge in a new network namespace, created without options.
class BridgeNfCallTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
    SKIP_IF(IsRunningWithHostinet());

    netns_ =
        ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/net", O_RDONLY));
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceeds());

    nl_ = ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
    PosixError err = NewLink(nl_, kSeq, "bridge", "br0", nullptr);
    // Native Linux kernels may not be built with CONFIG_BRIDGE.
    SKIP_IF(!IsRunningOnGvisor() && err.errno_value() == EOPNOTSUPP);
    ASSERT_NO_ERRNO(err);
    br_ = if_nametoindex("br0");
    ASSERT_NE(br_, 0);
  }

  void TearDown() override {
    if (netns_.get() >= 0) {
      EXPECT_THAT(setns(netns_.get(), CLONE_NEWNET), SyscallSucceeds());
    }
  }

  // Don't do cooperative save/restore because netstack state is not restored.
  // TODO(gvisor.dev/issue/4595): enable cooperative save tests.
  const DisableSave ds_;
  FileDescriptor netns_;
  FileDescriptor nl_;
  int br_ = 0;
};

constexpr int kNfCallAttrs[] = {IFLA_BR_NF_CALL_IPTABLES,
                                IFLA_BR_NF_CALL_IP6TABLES,
                                IFLA_BR_NF_CALL_ARPTABLES};

TEST_F(BridgeNfCallTest, ZeroIsAccepted) {
  const char* names[] = {"br1", "br2", "br3"};
  for (size_t i = 0; i < std::size(kNfCallAttrs); i++) {
    SCOPED_TRACE(kNfCallAttrs[i]);
    const uint8_t off = 0;
    EXPECT_NO_ERRNO(
        SetBridgeAttr(nl_, kSeq + 1, 0, names[i], kNfCallAttrs[i], &off, 1));
    EXPECT_NE(if_nametoindex(names[i]), 0);
    EXPECT_NO_ERRNO(
        SetBridgeAttr(nl_, kSeq + 2, br_, nullptr, kNfCallAttrs[i], &off, 1));
  }
}

// Linux: br_policy has the attributes as NLA_U8, so validate_nla rejects an
// empty one with ERANGE.
TEST_F(BridgeNfCallTest, EmptyIsOutOfRange) {
  for (int attr : kNfCallAttrs) {
    SCOPED_TRACE(attr);
    EXPECT_THAT(SetBridgeAttr(nl_, kSeq + 1, 0, "br1", attr, nullptr, 0),
                PosixErrorIs(ERANGE, ::testing::_));
    EXPECT_EQ(if_nametoindex("br1"), 0);
    EXPECT_THAT(SetBridgeAttr(nl_, kSeq + 2, br_, nullptr, attr, nullptr, 0),
                PosixErrorIs(ERANGE, ::testing::_));
  }
}

// gVisor passes bridged frames through netfilter as the
// net.bridge.bridge-nf-call-* sysctls say, without per-bridge options, so it
// doesn't accept enabling them.
TEST_F(BridgeNfCallTest, NonzeroIsNotSupported) {
  SKIP_IF(!IsRunningOnGvisor());
  for (int attr : kNfCallAttrs) {
    SCOPED_TRACE(attr);
    const uint8_t on = 1;
    EXPECT_THAT(SetBridgeAttr(nl_, kSeq + 1, 0, "br1", attr, &on, 1),
                PosixErrorIs(EOPNOTSUPP, ::testing::_));
    EXPECT_EQ(if_nametoindex("br1"), 0);
    EXPECT_THAT(SetBridgeAttr(nl_, kSeq + 2, br_, nullptr, attr, &on, 1),
                PosixErrorIs(EOPNOTSUPP, ::testing::_));
  }
}

constexpr char kBridgeSysctlDir[] = "/proc/sys/net/bridge/";
constexpr const char* kCallFiles[] = {"bridge-nf-call-arptables",
                                      "bridge-nf-call-iptables",
                                      "bridge-nf-call-ip6tables"};
constexpr const char* kTaggedFiles[] = {"bridge-nf-filter-vlan-tagged",
                                        "bridge-nf-filter-pppoe-tagged",
                                        "bridge-nf-pass-vlan-input-dev"};

std::string BridgeSysctl(const char* name) {
  return std::string(kBridgeSysctlDir) + name;
}

// Writes value to the sysctl file name in a single write.
PosixError WriteBridgeSysctl(const char* name, const std::string& value) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, Open(BridgeSysctl(name), O_WRONLY));
  RETURN_ERROR_IF_SYSCALL_FAIL(write(fd.get(), value.data(), value.size()));
  return NoError();
}

// The /proc/sys/net/bridge files of br_netfilter, in a new network namespace.
// gVisor shows the files of the root network namespace
// (gvisor.dev/issue/1833), so the test restores the values it changes.
// Natively, the files exist only when br_netfilter is loaded, which the test
// doesn't do.
class BridgeNetfilterSysctlTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
    SKIP_IF(IsRunningWithHostinet());

    netns_ =
        ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/net", O_RDONLY));
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceeds());
    struct stat st;
    int ret = stat(kBridgeSysctlDir, &st);
    SKIP_IF(!IsRunningOnGvisor() && ret < 0 && errno == ENOENT);
    ASSERT_THAT(ret, SyscallSucceeds());
    for (const char* name : kCallFiles) {
      saved_.push_back(
          ASSERT_NO_ERRNO_AND_VALUE(GetContents(BridgeSysctl(name))));
    }
  }

  void TearDown() override {
    for (size_t i = 0; i < saved_.size(); i++) {
      EXPECT_NO_ERRNO(WriteBridgeSysctl(kCallFiles[i], saved_[i]));
    }
    if (netns_.get() >= 0) {
      EXPECT_THAT(setns(netns_.get(), CLONE_NEWNET), SyscallSucceeds());
    }
  }

  FileDescriptor netns_;
  std::vector<std::string> saved_;
};

// Linux: brnf_net_init enables the call-* settings in every network namespace
// and leaves the others off.
TEST_F(BridgeNetfilterSysctlTest, Defaults) {
  for (const char* name : kCallFiles) {
    EXPECT_THAT(GetContents(BridgeSysctl(name)), IsPosixErrorOkAndHolds("1\n"))
        << name;
  }
  for (const char* name : kTaggedFiles) {
    EXPECT_THAT(GetContents(BridgeSysctl(name)), IsPosixErrorOkAndHolds("0\n"))
        << name;
  }
}

// Linux: brnf_sysctl_call_tables stores any nonzero value as 1.
TEST_F(BridgeNetfilterSysctlTest, CallStoresNonzeroAsOne) {
  for (const char* name : kCallFiles) {
    SCOPED_TRACE(name);
    for (const auto& [value, want] :
         std::vector<std::pair<std::string, std::string>>{
             {"0\n", "0\n"},
             {"1\n", "1\n"},
             {" 0 ", "0\n"},
             {"7", "1\n"},
             {"0", "0\n"},
             {"-1\n", "1\n"},
         }) {
      SCOPED_TRACE(value);
      ASSERT_NO_ERRNO(WriteBridgeSysctl(name, value));
      EXPECT_THAT(GetContents(BridgeSysctl(name)),
                  IsPosixErrorOkAndHolds(want));
    }
  }
}

// Linux: proc_dointvec rejects a write without a number, and leaves the value
// alone.
TEST_F(BridgeNetfilterSysctlTest, CallRejectsGarbage) {
  for (const char* name : kCallFiles) {
    SCOPED_TRACE(name);
    ASSERT_NO_ERRNO(WriteBridgeSysctl(name, "0"));
    for (const char* value : {"on\n", "\n", "x1"}) {
      SCOPED_TRACE(value);
      EXPECT_THAT(WriteBridgeSysctl(name, value),
                  PosixErrorIs(EINVAL, ::testing::_));
      EXPECT_THAT(GetContents(BridgeSysctl(name)),
                  IsPosixErrorOkAndHolds("0\n"));
    }
  }
}

TEST_F(BridgeNetfilterSysctlTest, CallSurvivesSaveRestore) {
  ASSERT_NO_ERRNO(WriteBridgeSysctl("bridge-nf-call-iptables", "0"));
  ASSERT_NO_ERRNO(WriteBridgeSysctl("bridge-nf-call-arptables", "0"));
  MaybeSave();
  EXPECT_THAT(GetContents(BridgeSysctl("bridge-nf-call-iptables")),
              IsPosixErrorOkAndHolds("0\n"));
  EXPECT_THAT(GetContents(BridgeSysctl("bridge-nf-call-ip6tables")),
              IsPosixErrorOkAndHolds("1\n"));
  EXPECT_THAT(GetContents(BridgeSysctl("bridge-nf-call-arptables")),
              IsPosixErrorOkAndHolds("0\n"));
}

TEST_F(BridgeNetfilterSysctlTest, TaggedAcceptZeroAndRejectGarbage) {
  for (const char* name : kTaggedFiles) {
    SCOPED_TRACE(name);
    EXPECT_NO_ERRNO(WriteBridgeSysctl(name, "0\n"));
    EXPECT_THAT(WriteBridgeSysctl(name, "on\n"),
                PosixErrorIs(EINVAL, ::testing::_));
    EXPECT_THAT(GetContents(BridgeSysctl(name)), IsPosixErrorOkAndHolds("0\n"));
  }
}

// gVisor never passes VLAN or PPPoE tagged frames through netfilter, so it
// doesn't accept enabling it.
TEST_F(BridgeNetfilterSysctlTest, TaggedRejectNonzero) {
  SKIP_IF(!IsRunningOnGvisor());
  for (const char* name : kTaggedFiles) {
    SCOPED_TRACE(name);
    EXPECT_THAT(WriteBridgeSysctl(name, "1\n"),
                PosixErrorIs(EINVAL, ::testing::_));
    EXPECT_THAT(GetContents(BridgeSysctl(name)), IsPosixErrorOkAndHolds("0\n"));
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
