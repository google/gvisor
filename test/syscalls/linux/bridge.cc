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
#include <string>
#include <string_view>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/file_descriptor.h"
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

// BridgeSaveRestoreTest records the calling thread's original network
// namespace in SetUp and restores it in TearDown so child-namespace tests do
// not leak namespace state.
class BridgeSaveRestoreTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(IsRunningWithHostinet());
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
    orig_netns_ =
        ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/net", O_RDONLY));
  }

  void TearDown() override {
    if (orig_netns_.get() >= 0) {
      EXPECT_THAT(setns(orig_netns_.get(), CLONE_NEWNET), SyscallSucceeds());
    }
  }

 private:
  FileDescriptor orig_netns_;
};

TEST_F(BridgeSaveRestoreTest, BridgeVethChildNetnsTCPAndUDPAcrossSave) {
  // Create an outer ephemeral network namespace holding br0 and one end of the
  // veth pair, and an inner child network namespace holding the peer veth.
  ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceeds());
  FileDescriptor outer_netns =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/net", O_RDONLY));
  FileDescriptor outer_nl =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

  Link outer_lo = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
  ASSERT_NO_ERRNO(LinkChangeFlags(outer_lo.index, IFF_UP, IFF_UP));

  PosixError err = NewLink(outer_nl, kSeq + 100, "bridge", "br0", nullptr);
  SKIP_IF(!IsRunningOnGvisor() && err.errno_value() == EOPNOTSUPP);
  ASSERT_NO_ERRNO(err);
  ASSERT_NO_ERRNO(NewLink(outer_nl, kSeq + 101, "veth", "veth_br", "veth_c"));

  const int br_idx = if_nametoindex("br0");
  ASSERT_NE(br_idx, 0);
  const int veth_br_idx = if_nametoindex("veth_br");
  ASSERT_NE(veth_br_idx, 0);
  const int veth_c_idx = if_nametoindex("veth_c");
  ASSERT_NE(veth_c_idx, 0);

  ASSERT_NO_ERRNO(SetLinkAttr(outer_nl, kSeq + 102, veth_br_idx, IFLA_MASTER,
                              &br_idx, sizeof(br_idx)));
  ASSERT_NO_ERRNO(LinkChangeFlags(br_idx, IFF_UP, IFF_UP));
  ASSERT_NO_ERRNO(LinkChangeFlags(veth_br_idx, IFF_UP, IFF_UP));

  struct in_addr br_ip = {};
  ASSERT_EQ(inet_pton(AF_INET, "10.200.0.1", &br_ip), 1);
  ASSERT_NO_ERRNO(
      LinkAddLocalAddr(outer_nl, br_idx, AF_INET, 24, &br_ip, sizeof(br_ip)));

  // Create the inner child namespace and move veth_c into it while renaming it
  // to eth0 in a single RTM_NEWLINK request.
  ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceeds());
  FileDescriptor inner_netns =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/net", O_RDONLY));
  FileDescriptor inner_nl =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));

  {
    LinkRequest move_req = {};
    move_req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(move_req.ifm));
    move_req.hdr.nlmsg_type = RTM_NEWLINK;
    move_req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    move_req.hdr.nlmsg_seq = kSeq + 103;
    move_req.ifm.ifi_index = veth_c_idx;
    int nsfd = inner_netns.get();
    AddAttr(&move_req, IFLA_NET_NS_FD, &nsfd, sizeof(nsfd));
    AddAttr(&move_req, IFLA_IFNAME, "eth0", strlen("eth0"));
    ASSERT_NO_ERRNO(NetlinkRequestAckOrError(outer_nl, kSeq + 103, &move_req,
                                             move_req.hdr.nlmsg_len));
  }

  // Like Linux dev_change_net_namespace, moving a link across namespaces
  // leaves it administratively DOWN in the destination namespace.
  std::vector<Link> inner_links =
      ASSERT_NO_ERRNO_AND_VALUE(DumpLinks(inner_nl));
  int eth0_idx = 0;
  for (const Link& link : inner_links) {
    if (link.name == "eth0") {
      eth0_idx = link.index;
      EXPECT_EQ(link.flags & IFF_UP, 0u);
    }
  }
  ASSERT_NE(eth0_idx, 0);

  Link inner_lo = ASSERT_NO_ERRNO_AND_VALUE(LoopbackLink());
  ASSERT_NO_ERRNO(LinkChangeFlags(inner_lo.index, IFF_UP, IFF_UP));
  ASSERT_NO_ERRNO(LinkChangeFlags(eth0_idx, IFF_UP, IFF_UP));

  struct in_addr inner_ip = {};
  ASSERT_EQ(inet_pton(AF_INET, "10.200.0.2", &inner_ip), 1);
  ASSERT_NO_ERRNO(LinkAddLocalAddr(inner_nl, eth0_idx, AF_INET, 24, &inner_ip,
                                   sizeof(inner_ip)));

  // Wait for bridge forwarding readiness using UDP sockets across namespaces.
  FileDescriptor inner_udp =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  struct sockaddr_in inner_udp_addr = {};
  inner_udp_addr.sin_family = AF_INET;
  inner_udp_addr.sin_addr = inner_ip;
  ASSERT_THAT(bind(inner_udp.get(), AsSockAddr(&inner_udp_addr),
                   sizeof(inner_udp_addr)),
              SyscallSucceeds());
  socklen_t addrlen = sizeof(inner_udp_addr);
  ASSERT_THAT(
      getsockname(inner_udp.get(), AsSockAddr(&inner_udp_addr), &addrlen),
      SyscallSucceeds());

  // Bind a listening TCP socket in inner_netns before switching back to
  // outer_netns.
  FileDescriptor inner_listen =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  struct sockaddr_in inner_tcp_addr = {};
  inner_tcp_addr.sin_family = AF_INET;
  inner_tcp_addr.sin_addr = inner_ip;
  ASSERT_THAT(bind(inner_listen.get(), AsSockAddr(&inner_tcp_addr),
                   sizeof(inner_tcp_addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(inner_listen.get(), 4), SyscallSucceeds());
  addrlen = sizeof(inner_tcp_addr);
  ASSERT_THAT(
      getsockname(inner_listen.get(), AsSockAddr(&inner_tcp_addr), &addrlen),
      SyscallSucceeds());

  ASSERT_THAT(setns(outer_netns.get(), CLONE_NEWNET), SyscallSucceeds());
  FileDescriptor outer_udp =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  const absl::Time ready_deadline = absl::Now() + absl::Seconds(10);
  bool bridge_ready = false;
  while (!bridge_ready && absl::Now() < ready_deadline) {
    const char probe[] = "ready";
    ASSERT_THAT(sendto(outer_udp.get(), probe, sizeof(probe), 0,
                       AsSockAddr(&inner_udp_addr), sizeof(inner_udp_addr)),
                SyscallSucceedsWithValue(sizeof(probe)));
    struct pollfd pfd = {.fd = inner_udp.get(), .events = POLLIN};
    if (RetryEINTR(poll)(&pfd, 1, 100) == 1) {
      char buf[16] = {};
      ASSERT_THAT(recv(inner_udp.get(), buf, sizeof(buf), 0),
                  SyscallSucceedsWithValue(sizeof(probe)));
      bridge_ready = true;
    }
  }
  ASSERT_TRUE(bridge_ready) << "bridge -> veth -> child netns did not forward";

  // Bind a listening TCP socket on br0 in outer_netns and connect a pre-save
  // TCP stream across br0 <-> eth0.
  FileDescriptor outer_listen =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  struct sockaddr_in outer_tcp_addr = {};
  outer_tcp_addr.sin_family = AF_INET;
  outer_tcp_addr.sin_addr = br_ip;
  ASSERT_THAT(bind(outer_listen.get(), AsSockAddr(&outer_tcp_addr),
                   sizeof(outer_tcp_addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(outer_listen.get(), 4), SyscallSucceeds());
  addrlen = sizeof(outer_tcp_addr);
  ASSERT_THAT(
      getsockname(outer_listen.get(), AsSockAddr(&outer_tcp_addr), &addrlen),
      SyscallSucceeds());

  FileDescriptor outer_client =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  ASSERT_THAT(
      RetryEINTR(connect)(outer_client.get(), AsSockAddr(&inner_tcp_addr),
                          sizeof(inner_tcp_addr)),
      SyscallSucceeds());
  FileDescriptor inner_accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(inner_listen.get(), nullptr, nullptr));

  constexpr std::string_view kPreMsg = "pre-save-bridge-veth";
  ASSERT_THAT(WriteFd(outer_client.get(), kPreMsg.data(), kPreMsg.size()),
              SyscallSucceedsWithValue(kPreMsg.size()));
  std::string recv_buf(kPreMsg.size(), '\0');
  ASSERT_THAT(ReadFd(inner_accepted.get(), recv_buf.data(), recv_buf.size()),
              SyscallSucceedsWithValue(recv_buf.size()));
  EXPECT_EQ(recv_buf, kPreMsg);

  MaybeSave();

  // Verify UDP datagram delivery across br0 <-> eth0 on pre-save UDP sockets
  // after checkpoint/restore.
  constexpr std::string_view kPostUdpMsg = "post-save-udp";
  ASSERT_THAT(sendto(outer_udp.get(), kPostUdpMsg.data(), kPostUdpMsg.size(), 0,
                     AsSockAddr(&inner_udp_addr), sizeof(inner_udp_addr)),
              SyscallSucceedsWithValue(kPostUdpMsg.size()));
  std::string udp_recv(kPostUdpMsg.size(), '\0');
  ASSERT_THAT(recv(inner_udp.get(), udp_recv.data(), udp_recv.size(), 0),
              SyscallSucceedsWithValue(udp_recv.size()));
  EXPECT_EQ(udp_recv, kPostUdpMsg);

  // Verify >MTU (8 KiB) bidirectional TCP transfer on the pre-save connection
  // after checkpoint/restore (exercising veth GSOGvisor MSS preservation and
  // preserved bridge FDB + ARP state).
  const std::string large_payload(8192, 'Z');
  ASSERT_THAT(
      WriteFd(inner_accepted.get(), large_payload.data(), large_payload.size()),
      SyscallSucceedsWithValue(large_payload.size()));
  std::string large_recv(large_payload.size(), '\0');
  ASSERT_THAT(ReadFd(outer_client.get(), large_recv.data(), large_recv.size()),
              SyscallSucceedsWithValue(large_recv.size()));
  EXPECT_EQ(large_recv, large_payload);

  const std::string reverse_payload(8192, 'Y');
  ASSERT_THAT(WriteFd(outer_client.get(), reverse_payload.data(),
                      reverse_payload.size()),
              SyscallSucceedsWithValue(reverse_payload.size()));
  large_recv.assign(reverse_payload.size(), '\0');
  ASSERT_THAT(
      ReadFd(inner_accepted.get(), large_recv.data(), large_recv.size()),
      SyscallSucceedsWithValue(large_recv.size()));
  EXPECT_EQ(large_recv, reverse_payload);

  // Verify post-save accept() on pre-save listening socket and post-save veth
  // creation in the restored child namespace.
  ASSERT_THAT(setns(inner_netns.get(), CLONE_NEWNET), SyscallSucceeds());
  FileDescriptor post_client =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  ASSERT_THAT(
      RetryEINTR(connect)(post_client.get(), AsSockAddr(&outer_tcp_addr),
                          sizeof(outer_tcp_addr)),
      SyscallSucceeds());
  FileDescriptor outer_accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(outer_listen.get(), nullptr, nullptr));
  constexpr std::string_view kPostMsg = "post-save-new-conn";
  ASSERT_THAT(WriteFd(post_client.get(), kPostMsg.data(), kPostMsg.size()),
              SyscallSucceedsWithValue(kPostMsg.size()));
  recv_buf.assign(kPostMsg.size(), '\0');
  ASSERT_THAT(ReadFd(outer_accepted.get(), recv_buf.data(), recv_buf.size()),
              SyscallSucceedsWithValue(recv_buf.size()));
  EXPECT_EQ(recv_buf, kPostMsg);

  ASSERT_NO_ERRNO(
      NewLink(inner_nl, kSeq + 104, "veth", "veth_post0", "veth_post1"));
  EXPECT_NE(if_nametoindex("veth_post0"), 0);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
