// Copyright 2018 Google LLC
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
#include <sys/socket.h>
#include <sys/types.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

struct sockaddr_in_common {
  sa_family_t sin_family;
  in_port_t sin_port;
};

struct SendtoTestParam {
  // Human readable description of test parameter.
  std::string description;

  // Test is broken in gVisor, skip.
  bool skip_on_gvisor;

  // Domain for the socket that will do the sending.
  int send_domain;

  // Address to bind for the socket that will do the sending.
  struct sockaddr_storage send_addr;
  socklen_t send_addr_len;  // 0 for unbound.

  // Address to connect to for the socket that will do the sending.
  struct sockaddr_storage connect_addr;
  socklen_t connect_addr_len;  // 0 for no connection.

  // Domain for the socket that will do the receiving.
  int recv_domain;

  // Address to bind for the socket that will do the receiving.
  struct sockaddr_storage recv_addr;
  socklen_t recv_addr_len;

  // Address to send to.
  struct sockaddr_storage sendto_addr;
  socklen_t sendto_addr_len;

  // Expected errno for the sendto call.
  std::vector<int> sendto_errnos;  // empty on success.
};

class SendtoTest : public ::testing::TestWithParam<SendtoTestParam> {
 protected:
  SendtoTest() {
    // gUnit uses printf, so so will we.
    printf("Testing with %s\n", GetParam().description.c_str());
  }
};

TEST_P(SendtoTest, Sendto) {
  auto param = GetParam();

  SKIP_IF(param.skip_on_gvisor && IsRunningOnGvisor());

  const FileDescriptor s1 =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(param.send_domain, SOCK_DGRAM, 0));
  const FileDescriptor s2 =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(param.recv_domain, SOCK_DGRAM, 0));

  if (param.send_addr_len > 0) {
    ASSERT_THAT(bind(s1.get(), reinterpret_cast<sockaddr*>(&param.send_addr),
                     param.send_addr_len),
                SyscallSucceeds());
  }

  if (param.connect_addr_len > 0) {
    ASSERT_THAT(
        connect(s1.get(), reinterpret_cast<sockaddr*>(&param.connect_addr),
                param.connect_addr_len),
        SyscallSucceeds());
  }

  ASSERT_THAT(bind(s2.get(), reinterpret_cast<sockaddr*>(&param.recv_addr),
                   param.recv_addr_len),
              SyscallSucceeds());

  struct sockaddr_storage real_recv_addr = {};
  socklen_t real_recv_addr_len = param.recv_addr_len;
  ASSERT_THAT(
      getsockname(s2.get(), reinterpret_cast<sockaddr*>(&real_recv_addr),
                  &real_recv_addr_len),
      SyscallSucceeds());

  ASSERT_EQ(real_recv_addr_len, param.recv_addr_len);

  int recv_port =
      reinterpret_cast<sockaddr_in_common*>(&real_recv_addr)->sin_port;

  struct sockaddr_storage sendto_addr = param.sendto_addr;
  reinterpret_cast<sockaddr_in_common*>(&sendto_addr)->sin_port = recv_port;

  char buf[20] = {};
  if (!param.sendto_errnos.empty()) {
    ASSERT_THAT(RetryEINTR(sendto)(s1.get(), buf, sizeof(buf), 0,
                                   reinterpret_cast<sockaddr*>(&sendto_addr),
                                   param.sendto_addr_len),
                SyscallFailsWithErrno(ElementOf(param.sendto_errnos)));
    return;
  }

  ASSERT_THAT(RetryEINTR(sendto)(s1.get(), buf, sizeof(buf), 0,
                                 reinterpret_cast<sockaddr*>(&sendto_addr),
                                 param.sendto_addr_len),
              SyscallSucceedsWithValue(sizeof(buf)));

  struct sockaddr_storage got_addr = {};
  socklen_t got_addr_len = sizeof(sockaddr_storage);
  ASSERT_THAT(RetryEINTR(recvfrom)(s2.get(), buf, sizeof(buf), 0,
                                   reinterpret_cast<sockaddr*>(&got_addr),
                                   &got_addr_len),
              SyscallSucceedsWithValue(sizeof(buf)));

  ASSERT_GT(got_addr_len, sizeof(sockaddr_in_common));
  int got_port = reinterpret_cast<sockaddr_in_common*>(&got_addr)->sin_port;

  struct sockaddr_storage sender_addr = {};
  socklen_t sender_addr_len = sizeof(sockaddr_storage);
  ASSERT_THAT(getsockname(s1.get(), reinterpret_cast<sockaddr*>(&sender_addr),
                          &sender_addr_len),
              SyscallSucceeds());

  ASSERT_GT(sender_addr_len, sizeof(sockaddr_in_common));
  int sender_port =
      reinterpret_cast<sockaddr_in_common*>(&sender_addr)->sin_port;

  EXPECT_EQ(got_port, sender_port);
}

socklen_t Ipv4Addr(sockaddr_storage* addr, int port = 0) {
  auto addr4 = reinterpret_cast<sockaddr_in*>(addr);
  addr4->sin_family = AF_INET;
  addr4->sin_port = port;
  inet_pton(AF_INET, "127.0.0.1", &addr4->sin_addr.s_addr);
  return sizeof(struct sockaddr_in);
}

socklen_t Ipv6Addr(sockaddr_storage* addr, int port = 0) {
  auto addr6 = reinterpret_cast<sockaddr_in6*>(addr);
  addr6->sin6_family = AF_INET6;
  addr6->sin6_port = port;
  inet_pton(AF_INET6, "::1", &addr6->sin6_addr.s6_addr);
  return sizeof(struct sockaddr_in6);
}

socklen_t Ipv4MappedIpv6Addr(sockaddr_storage* addr, int port = 0) {
  auto addr6 = reinterpret_cast<sockaddr_in6*>(addr);
  addr6->sin6_family = AF_INET6;
  addr6->sin6_port = port;
  inet_pton(AF_INET6, "::ffff:127.0.0.1", &addr6->sin6_addr.s6_addr);
  return sizeof(struct sockaddr_in6);
}

INSTANTIATE_TEST_SUITE_P(
    UdpBindTest, SendtoTest,
    ::testing::Values(
        []() {
          SendtoTestParam param = {};
          param.description = "IPv4 mapped IPv6 sendto IPv4 mapped IPv6";
          param.send_domain = AF_INET6;
          param.send_addr_len = Ipv4MappedIpv6Addr(&param.send_addr);
          param.recv_domain = AF_INET6;
          param.recv_addr_len = Ipv4MappedIpv6Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv4MappedIpv6Addr(&param.sendto_addr);
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "IPv6 sendto IPv6";
          param.send_domain = AF_INET6;
          param.send_addr_len = Ipv6Addr(&param.send_addr);
          param.recv_domain = AF_INET6;
          param.recv_addr_len = Ipv6Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv6Addr(&param.sendto_addr);
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "IPv4 sendto IPv4";
          param.send_domain = AF_INET;
          param.send_addr_len = Ipv4Addr(&param.send_addr);
          param.recv_domain = AF_INET;
          param.recv_addr_len = Ipv4Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv4Addr(&param.sendto_addr);
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "IPv4 mapped IPv6 sendto IPv4";
          param.send_domain = AF_INET6;
          param.send_addr_len = Ipv4MappedIpv6Addr(&param.send_addr);
          param.recv_domain = AF_INET;
          param.recv_addr_len = Ipv4Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv4MappedIpv6Addr(&param.sendto_addr);
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "IPv4 sendto IPv4 mapped IPv6";
          param.send_domain = AF_INET;
          param.send_addr_len = Ipv4Addr(&param.send_addr);
          param.recv_domain = AF_INET6;
          param.recv_addr_len = Ipv4MappedIpv6Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv4Addr(&param.sendto_addr);
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "unbound IPv6 sendto IPv4 mapped IPv6";
          param.send_domain = AF_INET6;
          param.recv_domain = AF_INET6;
          param.recv_addr_len = Ipv4MappedIpv6Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv4MappedIpv6Addr(&param.sendto_addr);
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "unbound IPv6 sendto IPv4";
          param.send_domain = AF_INET6;
          param.recv_domain = AF_INET;
          param.recv_addr_len = Ipv4Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv4MappedIpv6Addr(&param.sendto_addr);
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "IPv6 sendto IPv4";
          param.send_domain = AF_INET6;
          param.send_addr_len = Ipv6Addr(&param.send_addr);
          param.recv_domain = AF_INET;
          param.recv_addr_len = Ipv4Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv4MappedIpv6Addr(&param.sendto_addr);
          param.sendto_errnos = {ENETUNREACH};
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "IPv4 mapped IPv6 sendto IPv6";
          param.send_domain = AF_INET6;
          param.send_addr_len = Ipv4MappedIpv6Addr(&param.send_addr);
          param.recv_domain = AF_INET6;
          param.recv_addr_len = Ipv6Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv6Addr(&param.sendto_addr);
          param.sendto_errnos = {EAFNOSUPPORT};
          // The errno returned changed in Linux commit c8e6ad0829a723.
          param.sendto_errnos = {EINVAL, EAFNOSUPPORT};
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "connected IPv4 mapped IPv6 sendto IPv6";
          param.send_domain = AF_INET6;
          param.connect_addr_len =
              Ipv4MappedIpv6Addr(&param.connect_addr, 5000);
          param.recv_domain = AF_INET6;
          param.recv_addr_len = Ipv6Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv6Addr(&param.sendto_addr);
          // The errno returned changed in Linux commit c8e6ad0829a723.
          param.sendto_errnos = {EINVAL, EAFNOSUPPORT};
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "connected IPv6 sendto IPv4 mapped IPv6";
          // TODO(igudger): Determine if this inconsistent behavior is worth
          // implementing.
          param.skip_on_gvisor = true;
          param.send_domain = AF_INET6;
          param.connect_addr_len = Ipv6Addr(&param.connect_addr, 5000);
          param.recv_domain = AF_INET6;
          param.recv_addr_len = Ipv4MappedIpv6Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv4MappedIpv6Addr(&param.sendto_addr);
          return param;
        }(),
        []() {
          SendtoTestParam param = {};
          param.description = "connected IPv6 sendto IPv4";
          // TODO(igudger): Determine if this inconsistent behavior is worth
          // implementing.
          param.skip_on_gvisor = true;
          param.send_domain = AF_INET6;
          param.connect_addr_len = Ipv6Addr(&param.connect_addr, 5000);
          param.recv_domain = AF_INET;
          param.recv_addr_len = Ipv4Addr(&param.recv_addr);
          param.sendto_addr_len = Ipv4MappedIpv6Addr(&param.sendto_addr);
          return param;
        }()));

}  // namespace

}  // namespace testing
}  // namespace gvisor
