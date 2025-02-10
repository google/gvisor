// Copyright 2024 The gVisor Authors.
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

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

PosixErrorOr<void*> MakePacketMmapRing(int fd, const sockaddr* bind_addr,
                                       int bind_addr_size, tpacket_req* req,
                                       int version = TPACKET_V1) {
  RETURN_ERROR_IF_SYSCALL_FAIL(
      setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)));
  RETURN_ERROR_IF_SYSCALL_FAIL(
      setsockopt(fd, SOL_PACKET, PACKET_RX_RING, req, sizeof(*req)));
  RETURN_ERROR_IF_SYSCALL_FAIL(bind(fd, bind_addr, bind_addr_size));
  uint32_t sz = req->tp_block_size * req->tp_block_nr;
  return mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
}

// Tests that setting the RX ring works and fails if constraints are not met.
TEST(PacketMmapTest, SetRXRingFailsBadRequests) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, 0));

  // tp_block_size must be a multiple of tp_frame_size.
  tpacket_req req = {
      .tp_block_size = 100,
      .tp_block_nr = 1,
      .tp_frame_size = 64,
      .tp_frame_nr = 1,
  };
  ASSERT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_RX_RING, &req,
                         sizeof(req)),
              SyscallFailsWithErrno(EINVAL));
  // tp_frame_size mut be greater than TPACKET_HDR_LENGTH.
  req = {
      .tp_block_size = 100,
      .tp_block_nr = 1,
      .tp_frame_size = 10,
      .tp_frame_nr = 1,
  };
  ASSERT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_RX_RING, &req,
                         sizeof(req)),
              SyscallFailsWithErrno(EINVAL));
  // tp_frame_size must be a multiple of TPACKET_ALIGNMENT.
  req = {
      .tp_block_size = 200,
      .tp_block_nr = 1,
      .tp_frame_size = 100,
      .tp_frame_nr = 1,
  };
  ASSERT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_RX_RING, &req,
                         sizeof(req)),
              SyscallFailsWithErrno(EINVAL));
  // tp_frame_nr must be exactly frames_per_block / tp_block_nr.
  req = {
      .tp_block_size = 100,
      .tp_block_nr = 1,
      .tp_frame_size = 100,
      .tp_frame_nr = 2,
  };
  ASSERT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_RX_RING, &req,
                         sizeof(req)),
              SyscallFailsWithErrno(EINVAL));
  // tp_block_nr must be at least 1.
  req = {
      .tp_block_size = 100,
      .tp_block_nr = 0,
      .tp_frame_size = 100,
      .tp_frame_nr = 1,
  };
  ASSERT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_RX_RING, &req,
                         sizeof(req)),
              SyscallFailsWithErrno(EINVAL));
}

TEST(PacketMmapTest, Basic) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_IP),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, 0));

  uint32_t tp_frame_size = 65536 + 128;
  uint32_t tp_block_size = tp_frame_size * 32;
  uint32_t tp_block_nr = 2;
  uint32_t tp_frame_nr = (tp_block_size * tp_block_nr) / tp_frame_size;
  tpacket_req req = {
      .tp_block_size = tp_block_size,
      .tp_block_nr = tp_block_nr,
      .tp_frame_size = tp_frame_size,
      .tp_frame_nr = tp_frame_nr,
  };
  void* ring = ASSERT_NO_ERRNO_AND_VALUE(MakePacketMmapRing(
      mmap_sock.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
      sizeof(bind_addr), &req));
  auto ring_cleanup = Cleanup([ring, tp_block_size, tp_block_nr] {
    ASSERT_THAT(munmap(ring, tp_block_size * tp_block_nr), SyscallSucceeds());
  });

  std::string kMessage = "123abc";
  ASSERT_THAT(
      sendto(mmap_sock.get(), kMessage.c_str(), kMessage.size(), 0 /* flags */,
             reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)),
      SyscallSucceeds());

  tpacket_hdr* hdr = reinterpret_cast<tpacket_hdr*>(ring);
  struct pollfd pollset;
  pollset.fd = mmap_sock.get();
  pollset.revents = 0;
  pollset.events = POLLIN | POLLRDNORM | POLLERR;
  ASSERT_THAT(poll(&pollset, 1, -1), SyscallSucceeds());
  EXPECT_EQ(hdr->tp_status & TP_STATUS_USER, 1);
  EXPECT_EQ(hdr->tp_len, kMessage.size());
  EXPECT_EQ(hdr->tp_snaplen, kMessage.size());
  EXPECT_STREQ((char*)(hdr) + hdr->tp_net, kMessage.c_str());
}

TEST(PacketMmapTest, FillBlocks) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability ";
  }
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_IP),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, 0));

  uint32_t tp_frame_size = 65536 + 128;
  uint32_t tp_block_size = tp_frame_size * 32;
  uint32_t tp_block_nr = 2;
  uint32_t tp_frame_nr = (tp_block_size * tp_block_nr) / tp_frame_size;
  tpacket_req req = {
      .tp_block_size = tp_block_size,
      .tp_block_nr = tp_block_nr,
      .tp_frame_size = tp_frame_size,
      .tp_frame_nr = tp_frame_nr,
  };
  void* ring = ASSERT_NO_ERRNO_AND_VALUE(MakePacketMmapRing(
      mmap_sock.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
      sizeof(bind_addr), &req));
  auto ring_cleanup = Cleanup([ring, tp_block_size, tp_block_nr] {
    ASSERT_THAT(munmap(ring, tp_block_size * tp_block_nr), SyscallSucceeds());
  });

  std::string kMessage = "123abc";
  for (uint32_t i = 0; i < tp_frame_nr; i++) {
    ASSERT_THAT(
        sendto(mmap_sock.get(), kMessage.c_str(), kMessage.size(),
               0 /* flags */, reinterpret_cast<const sockaddr*>(&bind_addr),
               sizeof(bind_addr)),
        SyscallSucceeds());
  }

  // This send will wrap around to the first frame, but the ring buffer
  // should still be full.
  std::string kNewMessage = "HELLO!!!";
  ASSERT_THAT(
      sendto(mmap_sock.get(), kNewMessage.c_str(), kNewMessage.size(),
             0 /* flags */, reinterpret_cast<const sockaddr*>(&bind_addr),
             sizeof(bind_addr)),
      SyscallSucceeds());

  struct tpacket_hdr* hdr = reinterpret_cast<struct tpacket_hdr*>(ring);
  struct pollfd pollset;
  pollset.fd = mmap_sock.get();
  pollset.revents = 0;
  pollset.events = POLLIN | POLLRDNORM | POLLERR;
  ASSERT_THAT(poll(&pollset, 1, -1), SyscallSucceeds());
  EXPECT_EQ(hdr->tp_status & TP_STATUS_USER, 1);
  // We should not see the new message. It was dropped.
  EXPECT_STREQ((char*)(hdr) + hdr->tp_net, kMessage.c_str());

  // Wait until the last frame has been processed.
  hdr = reinterpret_cast<struct tpacket_hdr*>(
      reinterpret_cast<char*>(ring) + ((tp_frame_nr - 1) * tp_frame_size));
  while (!(hdr->tp_status & TP_STATUS_USER)) {
    absl::SleepFor(absl::Milliseconds(100));
  }

  // Mark all frames as kernel owned.
  for (uint32_t i = 0; i < tp_frame_nr; i++) {
    hdr = reinterpret_cast<tpacket_hdr*>(
        (reinterpret_cast<char*>(ring) + (i * tp_frame_size)));
    ASSERT_EQ(hdr->tp_status & TP_STATUS_USER, 1);
    hdr->tp_status = TP_STATUS_KERNEL;
  }

  ASSERT_THAT(
      sendto(mmap_sock.get(), kNewMessage.data(), kNewMessage.size(),
             0 /* flags */, reinterpret_cast<const sockaddr*>(&bind_addr),
             sizeof(bind_addr)),
      SyscallSucceeds());

  hdr = reinterpret_cast<struct tpacket_hdr*>(ring);
  pollset.fd = mmap_sock.get();
  pollset.revents = 0;
  pollset.events = POLLIN | POLLRDNORM | POLLERR;
  ASSERT_THAT(poll(&pollset, 1, -1), SyscallSucceeds());
  EXPECT_EQ(hdr->tp_status & TP_STATUS_USER, 1);
  // We should now see the new message.
  EXPECT_STREQ((char*)(hdr) + hdr->tp_net, kNewMessage.c_str());
}

TEST(PacketMmapTest, ZeroSizeRing) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_IP),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, 0));

  tpacket_req req = {};
  ASSERT_NO_ERRNO_AND_VALUE(MakePacketMmapRing(
      mmap_sock.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
      sizeof(bind_addr), &req));

  std::string kMessage = "123abc";
  ASSERT_THAT(
      sendto(mmap_sock.get(), kMessage.c_str(), kMessage.size(), 0 /* flags */,
             reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)),
      SyscallSucceeds());
}

TEST(PacketMmapTest, ConcurrentReadWrite) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_IP),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, 0));

  uint32_t tp_frame_size = 65536 + 128;
  uint32_t tp_block_size = tp_frame_size * 32;
  uint32_t tp_block_nr = 2;
  uint32_t tp_frame_nr = (tp_block_size * tp_block_nr) / tp_frame_size;
  tpacket_req req = {
      .tp_block_size = tp_block_size,
      .tp_block_nr = tp_block_nr,
      .tp_frame_size = tp_frame_size,
      .tp_frame_nr = tp_frame_nr,
  };
  void* ring = ASSERT_NO_ERRNO_AND_VALUE(MakePacketMmapRing(
      mmap_sock.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
      sizeof(bind_addr), &req));
  auto ring_cleanup = Cleanup([ring, tp_block_size, tp_block_nr] {
    ASSERT_THAT(munmap(ring, tp_block_size * tp_block_nr), SyscallSucceeds());
  });

  const std::string kMessage = "123abc";

  ScopedThread sender([&] {
    for (uint32_t i = 0; i < tp_frame_nr; i++) {
      ASSERT_THAT(
          sendto(mmap_sock.get(), kMessage.c_str(), kMessage.size(),
                 0 /* flags */, reinterpret_cast<const sockaddr*>(&bind_addr),
                 sizeof(bind_addr)),
          SyscallSucceeds());
    }
  });
  ScopedThread receiver([&] {
    struct tpacket_hdr* hdr = reinterpret_cast<struct tpacket_hdr*>(ring);
    for (uint32_t i = 0; i < tp_frame_nr; i++) {
      struct pollfd pollset;
      pollset.fd = mmap_sock.get();
      pollset.revents = 0;
      pollset.events = POLLIN | POLLRDNORM | POLLERR;
      ASSERT_THAT(poll(&pollset, 1, -1), SyscallSucceeds());
      EXPECT_EQ(hdr->tp_status & TP_STATUS_USER, 1);
      EXPECT_STREQ((char*)(hdr) + hdr->tp_net, kMessage.data());
    }
  });
  sender.Join();
  receiver.Join();
}

TEST(PacketMmapTest, RawPacket) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_ALL),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)));

  uint32_t tp_frame_size = 65536 + 128;
  uint32_t tp_block_size = tp_frame_size * 32;
  uint32_t tp_block_nr = 2;
  uint32_t tp_frame_nr = (tp_block_size * tp_block_nr) / tp_frame_size;
  tpacket_req req = {
      .tp_block_size = tp_block_size,
      .tp_block_nr = tp_block_nr,
      .tp_frame_size = tp_frame_size,
      .tp_frame_nr = tp_frame_nr,
  };
  void* ring = ASSERT_NO_ERRNO_AND_VALUE(MakePacketMmapRing(
      mmap_sock.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
      sizeof(bind_addr), &req));
  auto ring_cleanup = Cleanup([ring, tp_block_size, tp_block_nr] {
    ASSERT_THAT(munmap(ring, tp_block_size * tp_block_nr), SyscallSucceeds());
  });

  char buffer[1024];
  struct ethhdr* eth = (struct ethhdr*)buffer;
  char dest_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  memcpy(eth->h_dest, dest_mac, ETH_ALEN);
  char src_mac[] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
  memcpy(eth->h_source, src_mac, ETH_ALEN);
  eth->h_proto = htons(ETH_P_IP);
  std::string kMessage = "123abc";
  memcpy(buffer + ETH_HLEN, kMessage.data(), kMessage.size());

  ASSERT_THAT(
      sendto(mmap_sock.get(), buffer, ETH_HLEN + kMessage.size(), 0 /* flags */,
             reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)),
      SyscallSucceeds());

  tpacket_hdr* hdr = reinterpret_cast<tpacket_hdr*>(ring);
  struct pollfd pollset;
  pollset.fd = mmap_sock.get();
  pollset.revents = 0;
  pollset.events = POLLIN | POLLRDNORM | POLLERR;
  ASSERT_THAT(poll(&pollset, 1, -1), SyscallSucceeds());
  EXPECT_EQ(hdr->tp_status & TP_STATUS_USER, 1);
  EXPECT_EQ(hdr->tp_len, ETH_HLEN + kMessage.size());
  EXPECT_EQ(hdr->tp_snaplen, ETH_HLEN + kMessage.size());
  EXPECT_EQ(memcmp((char*)(hdr) + hdr->tp_mac, buffer, ETH_HLEN), 0);
  EXPECT_STREQ((char*)(hdr) + hdr->tp_net, kMessage.c_str());
}

TEST(PacketMmapTest, SetRingAfterMmapFails) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_ALL),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)));

  uint32_t tp_frame_size = 65536 + 128;
  uint32_t tp_block_size = tp_frame_size * 32;
  uint32_t tp_block_nr = 2;
  uint32_t tp_frame_nr = (tp_block_size * tp_block_nr) / tp_frame_size;
  tpacket_req req = {
      .tp_block_size = tp_block_size,
      .tp_block_nr = tp_block_nr,
      .tp_frame_size = tp_frame_size,
      .tp_frame_nr = tp_frame_nr,
  };
  void* ring = ASSERT_NO_ERRNO_AND_VALUE(MakePacketMmapRing(
      mmap_sock.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
      sizeof(bind_addr), &req));
  auto ring_cleanup = Cleanup([ring, tp_block_size, tp_block_nr] {
    ASSERT_THAT(munmap(ring, tp_block_size * tp_block_nr), SyscallSucceeds());
  });

  EXPECT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_RX_RING, &req,
                         sizeof(req)),
              SyscallFailsWithErrno(EBUSY));
}

TEST(PacketMmapTest, MmapCopy) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_ALL),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)));

  uint32_t tp_frame_size = 256;
  uint32_t tp_block_size = tp_frame_size * 32;
  uint32_t tp_block_nr = 2;
  uint32_t tp_frame_nr = (tp_block_size * tp_block_nr) / tp_frame_size;
  tpacket_req req = {
      .tp_block_size = tp_block_size,
      .tp_block_nr = tp_block_nr,
      .tp_frame_size = tp_frame_size,
      .tp_frame_nr = tp_frame_nr,
  };
  void* ring = ASSERT_NO_ERRNO_AND_VALUE(MakePacketMmapRing(
      mmap_sock.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
      sizeof(bind_addr), &req));
  auto ring_cleanup = Cleanup([ring, tp_block_size, tp_block_nr] {
    ASSERT_THAT(munmap(ring, tp_block_size * tp_block_nr), SyscallSucceeds());
  });

  std::string kMessage = "123abc" + std::string(1000, '*');
  ASSERT_THAT(
      sendto(mmap_sock.get(), kMessage.c_str(), kMessage.size(), 0 /* flags */,
             reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)),
      SyscallSucceeds());

  // Wait for the packet to become available on both sockets.
  struct pollfd pfd = {};
  pfd.fd = mmap_sock.get();
  pfd.revents = 0;
  pfd.events = POLLIN | POLLRDNORM | POLLERR;
  ASSERT_THAT(poll(&pfd, 1, -1), SyscallSucceeds());

  char buf[1024];
  socklen_t src_len = sizeof(kMessage);
  EXPECT_THAT(recvfrom(mmap_sock.get(), buf, sizeof(buf), 0,
                       reinterpret_cast<sockaddr*>(&bind_addr), &src_len),
              SyscallSucceedsWithValue(kMessage.size()));

  tpacket_hdr* hdr = reinterpret_cast<tpacket_hdr*>(ring);
  EXPECT_EQ(hdr->tp_status & (TP_STATUS_USER | TP_STATUS_COPY),
            TP_STATUS_USER | TP_STATUS_COPY);
  EXPECT_EQ(hdr->tp_snaplen, tp_frame_size - hdr->tp_mac);
}

TEST(PacketMmapTest, SetVersion) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, 0));

  int version = TPACKET_V2;
  EXPECT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_VERSION, &version,
                         sizeof(version)),
              SyscallSucceeds());
  version = TPACKET_V1;
  EXPECT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_VERSION, &version,
                         sizeof(version)),
              SyscallSucceeds());
  version = TPACKET_V3;
  EXPECT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_VERSION, &version,
                         sizeof(version)),
              SyscallFailsWithErrno(EINVAL));
  version = TPACKET_V1 + 100;
  EXPECT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_VERSION, &version,
                         sizeof(version)),
              SyscallFailsWithErrno(EINVAL));
}

TEST(PacketMmapTest, BasicV2) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_IP),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, 0));

  uint32_t tp_frame_size = 65536 + 128;
  uint32_t tp_block_size = tp_frame_size * 32;
  uint32_t tp_block_nr = 2;
  uint32_t tp_frame_nr = (tp_block_size * tp_block_nr) / tp_frame_size;
  tpacket_req req = {
      .tp_block_size = tp_block_size,
      .tp_block_nr = tp_block_nr,
      .tp_frame_size = tp_frame_size,
      .tp_frame_nr = tp_frame_nr,
  };
  void* ring = ASSERT_NO_ERRNO_AND_VALUE(MakePacketMmapRing(
      mmap_sock.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
      sizeof(bind_addr), &req, TPACKET_V2));
  auto ring_cleanup = Cleanup([ring, tp_block_size, tp_block_nr] {
    ASSERT_THAT(munmap(ring, tp_block_size * tp_block_nr), SyscallSucceeds());
  });

  std::string kMessage = "123abc";
  ASSERT_THAT(
      sendto(mmap_sock.get(), kMessage.c_str(), kMessage.size(), 0 /* flags */,
             reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)),
      SyscallSucceeds());

  tpacket2_hdr* hdr = reinterpret_cast<tpacket2_hdr*>(ring);
  struct pollfd pollset;
  pollset.fd = mmap_sock.get();
  pollset.revents = 0;
  pollset.events = POLLIN | POLLRDNORM | POLLERR;
  ASSERT_THAT(poll(&pollset, 1, -1), SyscallSucceeds());
  EXPECT_EQ(hdr->tp_status & TP_STATUS_USER, 1);
  EXPECT_EQ(hdr->tp_len, kMessage.size());
  EXPECT_EQ(hdr->tp_snaplen, kMessage.size());
  EXPECT_STREQ((char*)(hdr) + hdr->tp_net, kMessage.c_str());
}

TEST(PacketMMmapTest, GetPacketHdrLen) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }

  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, 0));

  int32_t val = TPACKET_V1;
  socklen_t val_len = sizeof(val);
  EXPECT_THAT(
      getsockopt(mmap_sock.get(), SOL_PACKET, PACKET_HDRLEN, &val, &val_len),
      SyscallSucceeds());
  EXPECT_EQ(val, sizeof(tpacket_hdr));

  val = TPACKET_V2;
  EXPECT_THAT(
      getsockopt(mmap_sock.get(), SOL_PACKET, PACKET_HDRLEN, &val, &val_len),
      SyscallSucceeds());
  EXPECT_EQ(val, sizeof(tpacket2_hdr));

  val = TPACKET_V3;
  EXPECT_THAT(
      getsockopt(mmap_sock.get(), SOL_PACKET, PACKET_HDRLEN, &val, &val_len),
      SyscallFailsWithErrno(EINVAL));
}

TEST(PacketMmapTest, PacketReserve) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_IP),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, 0));

  uint32_t tp_frame_size = 65536 + 128;
  uint32_t tp_block_size = tp_frame_size * 32;
  uint32_t tp_block_nr = 2;
  uint32_t tp_frame_nr = (tp_block_size * tp_block_nr) / tp_frame_size;
  tpacket_req req = {
      .tp_block_size = tp_block_size,
      .tp_block_nr = tp_block_nr,
      .tp_frame_size = tp_frame_size,
      .tp_frame_nr = tp_frame_nr,
  };

  int reserve = 20;
  ASSERT_THAT(setsockopt(mmap_sock.get(), SOL_PACKET, PACKET_RESERVE, &reserve,
                         sizeof(reserve)),
              SyscallSucceeds());
  void* ring = ASSERT_NO_ERRNO_AND_VALUE(MakePacketMmapRing(
      mmap_sock.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
      sizeof(bind_addr), &req, TPACKET_V2));
  auto ring_cleanup = Cleanup([ring, tp_block_size, tp_block_nr] {
    ASSERT_THAT(munmap(ring, tp_block_size * tp_block_nr), SyscallSucceeds());
  });

  std::string kMessage = "123abc";
  ASSERT_THAT(
      sendto(mmap_sock.get(), kMessage.c_str(), kMessage.size(), 0 /* flags */,
             reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)),
      SyscallSucceeds());

  tpacket2_hdr* hdr = reinterpret_cast<tpacket2_hdr*>(ring);
  struct pollfd pollset;
  pollset.fd = mmap_sock.get();
  pollset.revents = 0;
  pollset.events = POLLIN | POLLRDNORM | POLLERR;
  ASSERT_THAT(poll(&pollset, 1, -1), SyscallSucceeds());
  EXPECT_EQ(hdr->tp_status & TP_STATUS_USER, 1);
  EXPECT_EQ(hdr->tp_len, kMessage.size());
  EXPECT_EQ(hdr->tp_snaplen, kMessage.size());
  EXPECT_STREQ((char*)(hdr) + hdr->tp_net, kMessage.c_str());
  // PACKET_MMAP always adds a min 16 bytes between the sockaddr_ll and the
  // packet data.
  EXPECT_EQ(
      hdr->tp_net,
      TPACKET_ALIGN(sizeof(tpacket2_hdr) + sizeof(sockaddr_ll) + 16) + reserve);
}

TEST(PacketMmapTest, PacketStatistics) {
  if (!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW))) {
    ASSERT_THAT(socket(AF_PACKET, SOCK_RAW, 0), SyscallFailsWithErrno(EPERM));
    GTEST_SKIP() << "Missing packet socket capability";
  }
  sockaddr_ll bind_addr = {
      .sll_family = AF_PACKET,
      .sll_protocol = htons(ETH_P_IP),
      .sll_ifindex = ASSERT_NO_ERRNO_AND_VALUE(GetLoopbackIndex()),
      .sll_halen = ETH_ALEN,
  };
  FileDescriptor mmap_sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_DGRAM, 0));

  uint32_t tp_frame_size = 65536 + 128;
  uint32_t tp_block_size = tp_frame_size * 32;
  uint32_t tp_block_nr = 2;
  uint32_t tp_frame_nr = (tp_block_size * tp_block_nr) / tp_frame_size;
  tpacket_req req = {
      .tp_block_size = tp_block_size,
      .tp_block_nr = tp_block_nr,
      .tp_frame_size = tp_frame_size,
      .tp_frame_nr = tp_frame_nr,
  };
  void* ring = ASSERT_NO_ERRNO_AND_VALUE(MakePacketMmapRing(
      mmap_sock.get(), reinterpret_cast<const sockaddr*>(&bind_addr),
      sizeof(bind_addr), &req, TPACKET_V2));
  auto ring_cleanup = Cleanup([ring, tp_block_size, tp_block_nr] {
    ASSERT_THAT(munmap(ring, tp_block_size * tp_block_nr), SyscallSucceeds());
  });

  std::string kMessage = "123abc";
  for (uint32_t i = 0; i < tp_frame_nr; i++) {
    ASSERT_THAT(
        sendto(mmap_sock.get(), kMessage.c_str(), kMessage.size(),
               0 /* flags */, reinterpret_cast<const sockaddr*>(&bind_addr),
               sizeof(bind_addr)),
        SyscallSucceeds());
  }
  // After sending tp_frame_nr packets the buffer is full and all future sent
  // packets will be dropped.
  int expected_dropped = 20;
  for (int i = 0; i < expected_dropped; i++) {
    ASSERT_THAT(
        sendto(mmap_sock.get(), kMessage.c_str(), kMessage.size(),
               0 /* flags */, reinterpret_cast<const sockaddr*>(&bind_addr),
               sizeof(bind_addr)),
        SyscallSucceeds());
  }

  struct tpacket_stats stats;
  socklen_t stats_len = sizeof(stats);
  EXPECT_THAT(getsockopt(mmap_sock.get(), SOL_PACKET, PACKET_STATISTICS, &stats,
                         &stats_len),
              SyscallSucceeds());
  EXPECT_EQ(stats.tp_drops, expected_dropped);
  EXPECT_EQ(stats.tp_packets, tp_frame_nr + expected_dropped);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  // Some tests depend on delivering a signal to the main thread. Block the
  // target signal so that any other threads created by TestInit will also have
  // the signal blocked.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGALRM);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);

  gvisor::testing::TestInit(&argc, &argv);
  return gvisor::testing::RunAllTests();
}
