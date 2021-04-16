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
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

constexpr const char kProcNet[] = "/proc/net";
constexpr const char kIpForward[] = "/proc/sys/net/ipv4/ip_forward";
constexpr const char kRangeFile[] = "/proc/sys/net/ipv4/ip_local_port_range";

TEST(ProcNetSymlinkTarget, FileMode) {
  struct stat s;
  ASSERT_THAT(stat(kProcNet, &s), SyscallSucceeds());
  EXPECT_EQ(s.st_mode & S_IFMT, S_IFDIR);
  EXPECT_EQ(s.st_mode & 0777, 0555);
}

TEST(ProcNetSymlink, FileMode) {
  struct stat s;
  ASSERT_THAT(lstat(kProcNet, &s), SyscallSucceeds());
  EXPECT_EQ(s.st_mode & S_IFMT, S_IFLNK);
  EXPECT_EQ(s.st_mode & 0777, 0777);
}

TEST(ProcNetSymlink, Contents) {
  char buf[40] = {};
  int n = readlink(kProcNet, buf, sizeof(buf));
  ASSERT_THAT(n, SyscallSucceeds());

  buf[n] = 0;
  EXPECT_STREQ(buf, "self/net");
}

TEST(ProcNetIfInet6, Format) {
  auto ifinet6 = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/if_inet6"));
  EXPECT_THAT(ifinet6,
              ::testing::MatchesRegex(
                  // Ex: "00000000000000000000000000000001 01 80 10 80 lo\n"
                  "^([a-f0-9]{32}( [a-f0-9]{2}){4} +[a-z][a-z0-9]*\n)+$"));
}

TEST(ProcSysNetIpv4Sack, Exists) {
  EXPECT_THAT(open("/proc/sys/net/ipv4/tcp_sack", O_RDONLY), SyscallSucceeds());
}

TEST(ProcSysNetIpv4Sack, CanReadAndWrite) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_DAC_OVERRIDE))));

  auto const fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/sys/net/ipv4/tcp_sack", O_RDWR));

  char buf;
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  EXPECT_TRUE(buf == '0' || buf == '1') << "unexpected tcp_sack: " << buf;

  char to_write = (buf == '1') ? '0' : '1';
  EXPECT_THAT(PwriteFd(fd.get(), &to_write, sizeof(to_write), 0),
              SyscallSucceedsWithValue(sizeof(to_write)));

  buf = 0;
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));
  EXPECT_EQ(buf, to_write);
}

// DeviceEntry is an entry in /proc/net/dev
struct DeviceEntry {
  std::string name;
  uint64_t stats[16];
};

PosixErrorOr<std::vector<DeviceEntry>> GetDeviceMetricsFromProc(
    const std::string dev) {
  std::vector<std::string> lines = absl::StrSplit(dev, '\n');
  std::vector<DeviceEntry> entries;

  // /proc/net/dev prints 2 lines of headers followed by a line of metrics for
  // each network interface.
  for (unsigned i = 2; i < lines.size(); i++) {
    // Ignore empty lines.
    if (lines[i].empty()) {
      continue;
    }

    std::vector<std::string> values =
        absl::StrSplit(lines[i], ' ', absl::SkipWhitespace());

    // Interface name + 16 values.
    if (values.size() != 17) {
      return PosixError(EINVAL, "invalid line: " + lines[i]);
    }

    DeviceEntry entry;
    entry.name = values[0];
    // Skip the interface name and read only the values.
    for (unsigned j = 1; j < 17; j++) {
      uint64_t num;
      if (!absl::SimpleAtoi(values[j], &num)) {
        return PosixError(EINVAL, "invalid value: " + values[j]);
      }
      entry.stats[j - 1] = num;
    }

    entries.push_back(entry);
  }

  return entries;
}

// TEST(ProcNetDev, Format) tests that /proc/net/dev is parsable and
// contains at least one entry.
TEST(ProcNetDev, Format) {
  auto dev = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/dev"));
  auto entries = ASSERT_NO_ERRNO_AND_VALUE(GetDeviceMetricsFromProc(dev));

  EXPECT_GT(entries.size(), 0);
}

PosixErrorOr<uint64_t> GetSNMPMetricFromProc(const std::string snmp,
                                             const std::string& type,
                                             const std::string& item) {
  std::vector<std::string> snmp_vec = absl::StrSplit(snmp, '\n');

  // /proc/net/snmp prints a line of headers followed by a line of metrics.
  // Only search the headers.
  for (unsigned i = 0; i < snmp_vec.size(); i = i + 2) {
    if (!absl::StartsWith(snmp_vec[i], type)) continue;

    std::vector<std::string> fields =
        absl::StrSplit(snmp_vec[i], ' ', absl::SkipWhitespace());

    EXPECT_TRUE((i + 1) < snmp_vec.size());
    std::vector<std::string> values =
        absl::StrSplit(snmp_vec[i + 1], ' ', absl::SkipWhitespace());

    EXPECT_TRUE(!fields.empty() && fields.size() == values.size());

    // Metrics start at the first index.
    for (unsigned j = 1; j < fields.size(); j++) {
      if (fields[j] == item) {
        uint64_t val;
        if (!absl::SimpleAtoi(values[j], &val)) {
          return PosixError(EINVAL,
                            absl::StrCat("field is not a number: ", values[j]));
        }

        return val;
      }
    }
  }
  // We should never get here.
  return PosixError(
      EINVAL, absl::StrCat("failed to find ", type, "/", item, " in:", snmp));
}

TEST(ProcNetSnmp, TcpReset) {
  // TODO(gvisor.dev/issue/866): epsocket metrics are not savable.
  DisableSave ds;

  uint64_t oldAttemptFails;
  uint64_t oldActiveOpens;
  uint64_t oldOutRsts;
  auto snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  oldActiveOpens = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "ActiveOpens"));
  oldOutRsts =
      ASSERT_NO_ERRNO_AND_VALUE(GetSNMPMetricFromProc(snmp, "Tcp", "OutRsts"));
  oldAttemptFails = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "AttemptFails"));

  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));

  struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = htons(1234),
  };

  ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &(sin.sin_addr)), 1);
  ASSERT_THAT(connect(s.get(), (struct sockaddr*)&sin, sizeof(sin)),
              SyscallFailsWithErrno(ECONNREFUSED));

  uint64_t newAttemptFails;
  uint64_t newActiveOpens;
  uint64_t newOutRsts;
  snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  newActiveOpens = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "ActiveOpens"));
  newOutRsts =
      ASSERT_NO_ERRNO_AND_VALUE(GetSNMPMetricFromProc(snmp, "Tcp", "OutRsts"));
  newAttemptFails = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "AttemptFails"));

  EXPECT_EQ(oldActiveOpens, newActiveOpens - 1);
  EXPECT_EQ(oldOutRsts, newOutRsts - 1);
  EXPECT_EQ(oldAttemptFails, newAttemptFails - 1);
}

TEST(ProcNetSnmp, TcpEstab) {
  // TODO(gvisor.dev/issue/866): epsocket metrics are not savable.
  DisableSave ds;

  uint64_t oldEstabResets;
  uint64_t oldActiveOpens;
  uint64_t oldPassiveOpens;
  uint64_t oldCurrEstab;
  auto snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  oldActiveOpens = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "ActiveOpens"));
  oldPassiveOpens = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "PassiveOpens"));
  oldCurrEstab = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "CurrEstab"));
  oldEstabResets = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "EstabResets"));

  FileDescriptor s_listen =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = 0,
  };

  ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &(sin.sin_addr)), 1);
  ASSERT_THAT(bind(s_listen.get(), (struct sockaddr*)&sin, sizeof(sin)),
              SyscallSucceeds());
  ASSERT_THAT(listen(s_listen.get(), 1), SyscallSucceeds());

  // Get the port bound by the listening socket.
  socklen_t addrlen = sizeof(sin);
  ASSERT_THAT(getsockname(s_listen.get(), AsSockAddr(&sin), &addrlen),
              SyscallSucceeds());

  FileDescriptor s_connect =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  ASSERT_THAT(connect(s_connect.get(), (struct sockaddr*)&sin, sizeof(sin)),
              SyscallSucceeds());

  auto s_accept =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(s_listen.get(), nullptr, nullptr));

  uint64_t newEstabResets;
  uint64_t newActiveOpens;
  uint64_t newPassiveOpens;
  uint64_t newCurrEstab;
  snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  newActiveOpens = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "ActiveOpens"));
  newPassiveOpens = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "PassiveOpens"));
  newCurrEstab = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "CurrEstab"));

  EXPECT_EQ(oldActiveOpens, newActiveOpens - 1);
  EXPECT_EQ(oldPassiveOpens, newPassiveOpens - 1);
  EXPECT_EQ(oldCurrEstab, newCurrEstab - 2);

  // Send 1 byte from client to server.
  ASSERT_THAT(send(s_connect.get(), "a", 1, 0), SyscallSucceedsWithValue(1));

  constexpr int kPollTimeoutMs = 20000;  // Wait up to 20 seconds for the data.

  // Wait until server-side fd sees the data on its side but don't read it.
  struct pollfd poll_fd = {s_accept.get(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Now close server-side fd without reading the data which leads to a RST
  // packet sent to client side.
  s_accept.reset(-1);

  // Wait until client-side fd sees RST packet.
  struct pollfd poll_fd1 = {s_connect.get(), POLLIN, 0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd1, 1, kPollTimeoutMs),
              SyscallSucceedsWithValue(1));

  // Now close client-side fd.
  s_connect.reset(-1);

  // Wait until the process of the netstack.
  absl::SleepFor(absl::Seconds(1));

  snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  newCurrEstab = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "CurrEstab"));
  newEstabResets = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Tcp", "EstabResets"));

  EXPECT_EQ(oldCurrEstab, newCurrEstab);
  EXPECT_EQ(oldEstabResets, newEstabResets - 2);
}

TEST(ProcNetSnmp, UdpNoPorts) {
  // TODO(gvisor.dev/issue/866): epsocket metrics are not savable.
  DisableSave ds;

  uint64_t oldOutDatagrams;
  uint64_t oldNoPorts;
  auto snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  oldOutDatagrams = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Udp", "OutDatagrams"));
  oldNoPorts =
      ASSERT_NO_ERRNO_AND_VALUE(GetSNMPMetricFromProc(snmp, "Udp", "NoPorts"));

  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = htons(4444),
  };
  ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &(sin.sin_addr)), 1);
  ASSERT_THAT(sendto(s.get(), "a", 1, 0, (struct sockaddr*)&sin, sizeof(sin)),
              SyscallSucceedsWithValue(1));

  uint64_t newOutDatagrams;
  uint64_t newNoPorts;
  snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  newOutDatagrams = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Udp", "OutDatagrams"));
  newNoPorts =
      ASSERT_NO_ERRNO_AND_VALUE(GetSNMPMetricFromProc(snmp, "Udp", "NoPorts"));

  EXPECT_EQ(oldOutDatagrams, newOutDatagrams - 1);
  EXPECT_EQ(oldNoPorts, newNoPorts - 1);
}

TEST(ProcNetSnmp, UdpIn) {
  // TODO(gvisor.dev/issue/866): epsocket metrics are not savable.
  const DisableSave ds;

  uint64_t oldOutDatagrams;
  uint64_t oldInDatagrams;
  auto snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  oldOutDatagrams = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Udp", "OutDatagrams"));
  oldInDatagrams = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Udp", "InDatagrams"));

  std::cerr << "snmp: " << std::endl << snmp << std::endl;
  FileDescriptor server =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = htons(0),
  };
  ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &(sin.sin_addr)), 1);
  ASSERT_THAT(bind(server.get(), (struct sockaddr*)&sin, sizeof(sin)),
              SyscallSucceeds());
  // Get the port bound by the server socket.
  socklen_t addrlen = sizeof(sin);
  ASSERT_THAT(getsockname(server.get(), AsSockAddr(&sin), &addrlen),
              SyscallSucceeds());

  FileDescriptor client =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  ASSERT_THAT(
      sendto(client.get(), "a", 1, 0, (struct sockaddr*)&sin, sizeof(sin)),
      SyscallSucceedsWithValue(1));

  char buf[128];
  ASSERT_THAT(recvfrom(server.get(), buf, sizeof(buf), 0, NULL, NULL),
              SyscallSucceedsWithValue(1));

  uint64_t newOutDatagrams;
  uint64_t newInDatagrams;
  snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  std::cerr << "new snmp: " << std::endl << snmp << std::endl;
  newOutDatagrams = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Udp", "OutDatagrams"));
  newInDatagrams = ASSERT_NO_ERRNO_AND_VALUE(
      GetSNMPMetricFromProc(snmp, "Udp", "InDatagrams"));

  EXPECT_EQ(oldOutDatagrams, newOutDatagrams - 1);
  EXPECT_EQ(oldInDatagrams, newInDatagrams - 1);
}

TEST(ProcNetSnmp, CheckNetStat) {
  // TODO(b/155123175): SNMP and netstat don't work on gVisor.
  SKIP_IF(IsRunningOnGvisor());

  std::string contents =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/netstat"));

  int name_count = 0;
  int value_count = 0;
  std::vector<absl::string_view> lines = absl::StrSplit(contents, '\n');
  for (size_t i = 0; i + 1 < lines.size(); i += 2) {
    std::vector<absl::string_view> names =
        absl::StrSplit(lines[i], absl::ByAnyChar("\t "));
    std::vector<absl::string_view> values =
        absl::StrSplit(lines[i + 1], absl::ByAnyChar("\t "));
    EXPECT_EQ(names.size(), values.size()) << " mismatch in lines '" << lines[i]
                                           << "' and '" << lines[i + 1] << "'";
    for (size_t j = 0; j < names.size() && j < values.size(); ++j) {
      if (names[j] == "TCPOrigDataSent" || names[j] == "TCPSynRetrans" ||
          names[j] == "TCPDSACKRecv" || names[j] == "TCPDSACKOfoRecv") {
        ++name_count;
        int64_t val;
        if (absl::SimpleAtoi(values[j], &val)) {
          ++value_count;
        }
      }
    }
  }
  EXPECT_EQ(name_count, 4);
  EXPECT_EQ(value_count, 4);
}

TEST(ProcNetSnmp, Stat) {
  struct stat st = {};
  ASSERT_THAT(stat("/proc/net/snmp", &st), SyscallSucceeds());
}

TEST(ProcNetSnmp, CheckSnmp) {
  // TODO(b/155123175): SNMP and netstat don't work on gVisor.
  SKIP_IF(IsRunningOnGvisor());

  std::string contents =
      ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));

  int name_count = 0;
  int value_count = 0;
  std::vector<absl::string_view> lines = absl::StrSplit(contents, '\n');
  for (size_t i = 0; i + 1 < lines.size(); i += 2) {
    std::vector<absl::string_view> names =
        absl::StrSplit(lines[i], absl::ByAnyChar("\t "));
    std::vector<absl::string_view> values =
        absl::StrSplit(lines[i + 1], absl::ByAnyChar("\t "));
    EXPECT_EQ(names.size(), values.size()) << " mismatch in lines '" << lines[i]
                                           << "' and '" << lines[i + 1] << "'";
    for (size_t j = 0; j < names.size() && j < values.size(); ++j) {
      if (names[j] == "RetransSegs") {
        ++name_count;
        int64_t val;
        if (absl::SimpleAtoi(values[j], &val)) {
          ++value_count;
        }
      }
    }
  }
  EXPECT_EQ(name_count, 1);
  EXPECT_EQ(value_count, 1);
}

TEST(ProcSysNetIpv4Recovery, Exists) {
  EXPECT_THAT(open("/proc/sys/net/ipv4/tcp_recovery", O_RDONLY),
              SyscallSucceeds());
}

TEST(ProcSysNetIpv4Recovery, CanReadAndWrite) {
  // TODO(b/162988252): Enable save/restore for this test after the bug is
  // fixed.
  DisableSave ds;

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_DAC_OVERRIDE))));

  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open("/proc/sys/net/ipv4/tcp_recovery", O_RDWR));

  char buf[10] = {'\0'};
  char to_write = '2';

  // Check initial value is set to 1.
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(to_write) + 1));
  if (IsRunningOnGvisor()) {
    // TODO(gvisor.dev/issue/5243): TCPRACKLossDetection = 1 should be turned on
    // by default.
    EXPECT_EQ(strcmp(buf, "0\n"), 0);
  } else {
    EXPECT_EQ(strcmp(buf, "1\n"), 0);
  }

  // Set tcp_recovery to one of the allowed constants.
  EXPECT_THAT(PwriteFd(fd.get(), &to_write, sizeof(to_write), 0),
              SyscallSucceedsWithValue(sizeof(to_write)));
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(to_write) + 1));
  EXPECT_EQ(strcmp(buf, "2\n"), 0);

  // Set tcp_recovery to any random value.
  char kMessage[] = "100";
  EXPECT_THAT(PwriteFd(fd.get(), kMessage, strlen(kMessage), 0),
              SyscallSucceedsWithValue(strlen(kMessage)));
  EXPECT_THAT(PreadFd(fd.get(), buf, sizeof(kMessage), 0),
              SyscallSucceedsWithValue(sizeof(kMessage)));
  EXPECT_EQ(strcmp(buf, "100\n"), 0);
}

TEST(ProcSysNetIpv4IpForward, Exists) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(kIpForward, O_RDONLY));
}

TEST(ProcSysNetIpv4IpForward, DefaultValueEqZero) {
  // Test is only valid in sandbox. Not hermetic in native tests
  // running on a arbitrary machine.
  SKIP_IF(!IsRunningOnGvisor());
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(Open(kIpForward, O_RDONLY));

  char buf = 101;
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  EXPECT_EQ(buf, '0') << "unexpected ip_forward: " << buf;
}

TEST(ProcSysNetIpv4IpForward, CanReadAndWrite) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_DAC_OVERRIDE))));

  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(Open(kIpForward, O_RDWR));

  char buf;
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  EXPECT_TRUE(buf == '0' || buf == '1') << "unexpected ip_forward: " << buf;

  // constexpr char to_write = '1';
  char to_write = (buf == '1') ? '0' : '1';
  EXPECT_THAT(PwriteFd(fd.get(), &to_write, sizeof(to_write), 0),
              SyscallSucceedsWithValue(sizeof(to_write)));

  buf = 0;
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));
  EXPECT_EQ(buf, to_write);
}

TEST(ProcSysNetPortRange, CanReadAndWrite) {
  int min;
  int max;
  std::string rangefile = ASSERT_NO_ERRNO_AND_VALUE(GetContents(kRangeFile));
  ASSERT_EQ(rangefile.back(), '\n');
  rangefile.pop_back();
  std::vector<std::string> range =
      absl::StrSplit(rangefile, absl::ByAnyChar("\t "));
  ASSERT_GT(range.size(), 1);
  ASSERT_TRUE(absl::SimpleAtoi(range.front(), &min));
  ASSERT_TRUE(absl::SimpleAtoi(range.back(), &max));
  EXPECT_LE(min, max);

  // If the file isn't writable, there's nothing else to do here.
  if (access(kRangeFile, W_OK)) {
    return;
  }

  constexpr int kSize = 77;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(kRangeFile, O_WRONLY | O_TRUNC, 0));
  max = min + kSize;
  const std::string small_range = absl::StrFormat("%d %d", min, max);
  ASSERT_THAT(write(fd.get(), small_range.c_str(), small_range.size()),
              SyscallSucceedsWithValue(small_range.size()));

  rangefile = ASSERT_NO_ERRNO_AND_VALUE(GetContents(kRangeFile));
  ASSERT_EQ(rangefile.back(), '\n');
  rangefile.pop_back();
  range = absl::StrSplit(rangefile, absl::ByAnyChar("\t "));
  ASSERT_GT(range.size(), 1);
  ASSERT_TRUE(absl::SimpleAtoi(range.front(), &min));
  ASSERT_TRUE(absl::SimpleAtoi(range.back(), &max));
  EXPECT_EQ(min + kSize, max);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
