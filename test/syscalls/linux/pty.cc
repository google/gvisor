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

#include <fcntl.h>
#include <linux/capability.h>
#include <linux/major.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <iostream>

#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/pty_util.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::AnyOf;
using ::testing::Contains;
using ::testing::Eq;
using ::testing::Not;
using SubprocessCallback = std::function<void()>;

// Tests Unix98 pseudoterminals.
//
// These tests assume that /dev/ptmx exists and is associated with a devpts
// filesystem mounted at /dev/pts/. While a Linux distribution could
// theoretically place those anywhere, glibc expects those locations, so they
// are effectively fixed.

// Minor device number for an unopened ptmx file.
constexpr int kPtmxMinor = 2;

// The timeout when polling for data from a pty. When data is written to one end
// of a pty, Linux asynchronously makes it available to the other end, so we
// have to wait.
constexpr absl::Duration kTimeout = absl::Seconds(20);

// The maximum line size in bytes returned per read from a pty file.
constexpr int kMaxLineSize = 4096;

constexpr char kMasterPath[] = "/dev/ptmx";

// glibc defines its own, different, version of struct termios. We care about
// what the kernel does, not glibc.
#define KERNEL_NCCS 19
struct kernel_termios {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[KERNEL_NCCS];
};

bool operator==(struct kernel_termios const& a,
                struct kernel_termios const& b) {
  return memcmp(&a, &b, sizeof(a)) == 0;
}

// Returns the termios-style control character for the passed character.
//
// e.g., for Ctrl-C, i.e., ^C, call ControlCharacter('C').
//
// Standard control characters are ASCII bytes 0 through 31.
constexpr char ControlCharacter(char c) {
  // A is 1, B is 2, etc.
  return c - 'A' + 1;
}

// Returns the printable character the given control character represents.
constexpr char FromControlCharacter(char c) { return c + 'A' - 1; }

// Returns true if c is a control character.
//
// Standard control characters are ASCII bytes 0 through 31.
constexpr bool IsControlCharacter(char c) { return c <= 31; }

struct Field {
  const char* name;
  uint64_t mask;
  uint64_t value;
};

// ParseFields returns a string representation of value, using the names in
// fields.
std::string ParseFields(const Field* fields, size_t len, uint64_t value) {
  bool first = true;
  std::string s;
  for (size_t i = 0; i < len; i++) {
    const Field f = fields[i];
    if ((value & f.mask) == f.value) {
      if (!first) {
        s += "|";
      }
      s += f.name;
      first = false;
      value &= ~f.mask;
    }
  }

  if (value) {
    if (!first) {
      s += "|";
    }
    absl::StrAppend(&s, value);
  }

  return s;
}

const Field kIflagFields[] = {
    {"IGNBRK", IGNBRK, IGNBRK}, {"BRKINT", BRKINT, BRKINT},
    {"IGNPAR", IGNPAR, IGNPAR}, {"PARMRK", PARMRK, PARMRK},
    {"INPCK", INPCK, INPCK},    {"ISTRIP", ISTRIP, ISTRIP},
    {"INLCR", INLCR, INLCR},    {"IGNCR", IGNCR, IGNCR},
    {"ICRNL", ICRNL, ICRNL},    {"IUCLC", IUCLC, IUCLC},
    {"IXON", IXON, IXON},       {"IXANY", IXANY, IXANY},
    {"IXOFF", IXOFF, IXOFF},    {"IMAXBEL", IMAXBEL, IMAXBEL},
    {"IUTF8", IUTF8, IUTF8},
};

const Field kOflagFields[] = {
    {"OPOST", OPOST, OPOST}, {"OLCUC", OLCUC, OLCUC},
    {"ONLCR", ONLCR, ONLCR}, {"OCRNL", OCRNL, OCRNL},
    {"ONOCR", ONOCR, ONOCR}, {"ONLRET", ONLRET, ONLRET},
    {"OFILL", OFILL, OFILL}, {"OFDEL", OFDEL, OFDEL},
    {"NL0", NLDLY, NL0},     {"NL1", NLDLY, NL1},
    {"CR0", CRDLY, CR0},     {"CR1", CRDLY, CR1},
    {"CR2", CRDLY, CR2},     {"CR3", CRDLY, CR3},
    {"TAB0", TABDLY, TAB0},  {"TAB1", TABDLY, TAB1},
    {"TAB2", TABDLY, TAB2},  {"TAB3", TABDLY, TAB3},
    {"BS0", BSDLY, BS0},     {"BS1", BSDLY, BS1},
    {"FF0", FFDLY, FF0},     {"FF1", FFDLY, FF1},
    {"VT0", VTDLY, VT0},     {"VT1", VTDLY, VT1},
    {"XTABS", XTABS, XTABS},
};

#ifndef IBSHIFT
// Shift from CBAUD to CIBAUD.
#define IBSHIFT 16
#endif

const Field kCflagFields[] = {
    {"B0", CBAUD, B0},
    {"B50", CBAUD, B50},
    {"B75", CBAUD, B75},
    {"B110", CBAUD, B110},
    {"B134", CBAUD, B134},
    {"B150", CBAUD, B150},
    {"B200", CBAUD, B200},
    {"B300", CBAUD, B300},
    {"B600", CBAUD, B600},
    {"B1200", CBAUD, B1200},
    {"B1800", CBAUD, B1800},
    {"B2400", CBAUD, B2400},
    {"B4800", CBAUD, B4800},
    {"B9600", CBAUD, B9600},
    {"B19200", CBAUD, B19200},
    {"B38400", CBAUD, B38400},
    {"CS5", CSIZE, CS5},
    {"CS6", CSIZE, CS6},
    {"CS7", CSIZE, CS7},
    {"CS8", CSIZE, CS8},
    {"CSTOPB", CSTOPB, CSTOPB},
    {"CREAD", CREAD, CREAD},
    {"PARENB", PARENB, PARENB},
    {"PARODD", PARODD, PARODD},
    {"HUPCL", HUPCL, HUPCL},
    {"CLOCAL", CLOCAL, CLOCAL},
    {"B57600", CBAUD, B57600},
    {"B115200", CBAUD, B115200},
    {"B230400", CBAUD, B230400},
    {"B460800", CBAUD, B460800},
    {"B500000", CBAUD, B500000},
    {"B576000", CBAUD, B576000},
    {"B921600", CBAUD, B921600},
    {"B1000000", CBAUD, B1000000},
    {"B1152000", CBAUD, B1152000},
    {"B1500000", CBAUD, B1500000},
    {"B2000000", CBAUD, B2000000},
    {"B2500000", CBAUD, B2500000},
    {"B3000000", CBAUD, B3000000},
    {"B3500000", CBAUD, B3500000},
    {"B4000000", CBAUD, B4000000},
    {"CMSPAR", CMSPAR, CMSPAR},
    {"CRTSCTS", CRTSCTS, CRTSCTS},
    {"IB0", CIBAUD, B0 << IBSHIFT},
    {"IB50", CIBAUD, B50 << IBSHIFT},
    {"IB75", CIBAUD, B75 << IBSHIFT},
    {"IB110", CIBAUD, B110 << IBSHIFT},
    {"IB134", CIBAUD, B134 << IBSHIFT},
    {"IB150", CIBAUD, B150 << IBSHIFT},
    {"IB200", CIBAUD, B200 << IBSHIFT},
    {"IB300", CIBAUD, B300 << IBSHIFT},
    {"IB600", CIBAUD, B600 << IBSHIFT},
    {"IB1200", CIBAUD, B1200 << IBSHIFT},
    {"IB1800", CIBAUD, B1800 << IBSHIFT},
    {"IB2400", CIBAUD, B2400 << IBSHIFT},
    {"IB4800", CIBAUD, B4800 << IBSHIFT},
    {"IB9600", CIBAUD, B9600 << IBSHIFT},
    {"IB19200", CIBAUD, B19200 << IBSHIFT},
    {"IB38400", CIBAUD, B38400 << IBSHIFT},
    {"IB57600", CIBAUD, B57600 << IBSHIFT},
    {"IB115200", CIBAUD, B115200 << IBSHIFT},
    {"IB230400", CIBAUD, B230400 << IBSHIFT},
    {"IB460800", CIBAUD, B460800 << IBSHIFT},
    {"IB500000", CIBAUD, B500000 << IBSHIFT},
    {"IB576000", CIBAUD, B576000 << IBSHIFT},
    {"IB921600", CIBAUD, B921600 << IBSHIFT},
    {"IB1000000", CIBAUD, B1000000 << IBSHIFT},
    {"IB1152000", CIBAUD, B1152000 << IBSHIFT},
    {"IB1500000", CIBAUD, B1500000 << IBSHIFT},
    {"IB2000000", CIBAUD, B2000000 << IBSHIFT},
    {"IB2500000", CIBAUD, B2500000 << IBSHIFT},
    {"IB3000000", CIBAUD, B3000000 << IBSHIFT},
    {"IB3500000", CIBAUD, B3500000 << IBSHIFT},
    {"IB4000000", CIBAUD, B4000000 << IBSHIFT},
};

const Field kLflagFields[] = {
    {"ISIG", ISIG, ISIG},          {"ICANON", ICANON, ICANON},
    {"XCASE", XCASE, XCASE},       {"ECHO", ECHO, ECHO},
    {"ECHOE", ECHOE, ECHOE},       {"ECHOK", ECHOK, ECHOK},
    {"ECHONL", ECHONL, ECHONL},    {"NOFLSH", NOFLSH, NOFLSH},
    {"TOSTOP", TOSTOP, TOSTOP},    {"ECHOCTL", ECHOCTL, ECHOCTL},
    {"ECHOPRT", ECHOPRT, ECHOPRT}, {"ECHOKE", ECHOKE, ECHOKE},
    {"FLUSHO", FLUSHO, FLUSHO},    {"PENDIN", PENDIN, PENDIN},
    {"IEXTEN", IEXTEN, IEXTEN},    {"EXTPROC", EXTPROC, EXTPROC},
};

std::string FormatCC(char c) {
  if (isgraph(c)) {
    return std::string(1, c);
  } else if (c == ' ') {
    return " ";
  } else if (c == '\t') {
    return "\\t";
  } else if (c == '\r') {
    return "\\r";
  } else if (c == '\n') {
    return "\\n";
  } else if (c == '\0') {
    return "\\0";
  } else if (IsControlCharacter(c)) {
    return absl::StrCat("^", std::string(1, FromControlCharacter(c)));
  }
  return absl::StrCat("\\x", absl::Hex(c));
}

std::ostream& operator<<(std::ostream& os, struct kernel_termios const& a) {
  os << "{ c_iflag = "
     << ParseFields(kIflagFields, ABSL_ARRAYSIZE(kIflagFields), a.c_iflag);
  os << ", c_oflag = "
     << ParseFields(kOflagFields, ABSL_ARRAYSIZE(kOflagFields), a.c_oflag);
  os << ", c_cflag = "
     << ParseFields(kCflagFields, ABSL_ARRAYSIZE(kCflagFields), a.c_cflag);
  os << ", c_lflag = "
     << ParseFields(kLflagFields, ABSL_ARRAYSIZE(kLflagFields), a.c_lflag);
  os << ", c_line = " << a.c_line;
  os << ", c_cc = { [VINTR] = '" << FormatCC(a.c_cc[VINTR]);
  os << "', [VQUIT] = '" << FormatCC(a.c_cc[VQUIT]);
  os << "', [VERASE] = '" << FormatCC(a.c_cc[VERASE]);
  os << "', [VKILL] = '" << FormatCC(a.c_cc[VKILL]);
  os << "', [VEOF] = '" << FormatCC(a.c_cc[VEOF]);
  os << "', [VTIME] = '" << static_cast<int>(a.c_cc[VTIME]);
  os << "', [VMIN] = " << static_cast<int>(a.c_cc[VMIN]);
  os << ", [VSWTC] = '" << FormatCC(a.c_cc[VSWTC]);
  os << "', [VSTART] = '" << FormatCC(a.c_cc[VSTART]);
  os << "', [VSTOP] = '" << FormatCC(a.c_cc[VSTOP]);
  os << "', [VSUSP] = '" << FormatCC(a.c_cc[VSUSP]);
  os << "', [VEOL] = '" << FormatCC(a.c_cc[VEOL]);
  os << "', [VREPRINT] = '" << FormatCC(a.c_cc[VREPRINT]);
  os << "', [VDISCARD] = '" << FormatCC(a.c_cc[VDISCARD]);
  os << "', [VWERASE] = '" << FormatCC(a.c_cc[VWERASE]);
  os << "', [VLNEXT] = '" << FormatCC(a.c_cc[VLNEXT]);
  os << "', [VEOL2] = '" << FormatCC(a.c_cc[VEOL2]);
  os << "'}";
  return os;
}

// Return the default termios settings for a new terminal.
struct kernel_termios DefaultTermios() {
  struct kernel_termios t = {};
  t.c_iflag = IXON | ICRNL;
  t.c_oflag = OPOST | ONLCR;
  t.c_cflag = B38400 | CSIZE | CS8 | CREAD;
  t.c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;
  t.c_line = 0;
  t.c_cc[VINTR] = ControlCharacter('C');
  t.c_cc[VQUIT] = ControlCharacter('\\');
  t.c_cc[VERASE] = '\x7f';
  t.c_cc[VKILL] = ControlCharacter('U');
  t.c_cc[VEOF] = ControlCharacter('D');
  t.c_cc[VTIME] = '\0';
  t.c_cc[VMIN] = 1;
  t.c_cc[VSWTC] = '\0';
  t.c_cc[VSTART] = ControlCharacter('Q');
  t.c_cc[VSTOP] = ControlCharacter('S');
  t.c_cc[VSUSP] = ControlCharacter('Z');
  t.c_cc[VEOL] = '\0';
  t.c_cc[VREPRINT] = ControlCharacter('R');
  t.c_cc[VDISCARD] = ControlCharacter('O');
  t.c_cc[VWERASE] = ControlCharacter('W');
  t.c_cc[VLNEXT] = ControlCharacter('V');
  t.c_cc[VEOL2] = '\0';
  return t;
}

// PollAndReadFd tries to read count bytes from buf within timeout.
//
// Returns a partial read if some bytes were read.
//
// fd must be non-blocking.
PosixErrorOr<size_t> PollAndReadFd(int fd, void* buf, size_t count,
                                   absl::Duration timeout) {
  absl::Time end = absl::Now() + timeout;

  size_t completed = 0;
  absl::Duration remaining;
  while ((remaining = end - absl::Now()) > absl::ZeroDuration()) {
    struct pollfd pfd = {fd, POLLIN, 0};
    int ret = RetryEINTR(poll)(&pfd, 1, absl::ToInt64Milliseconds(remaining));
    if (ret < 0) {
      return PosixError(errno, "poll failed");
    } else if (ret == 0) {
      // Timed out.
      continue;
    } else if (ret != 1) {
      return PosixError(EINVAL, absl::StrCat("Bad poll ret ", ret));
    }

    ssize_t n =
        ReadFd(fd, static_cast<char*>(buf) + completed, count - completed);
    if (n < 0) {
      if (errno == EAGAIN) {
        // Linux sometimes returns EAGAIN from this read, despite the fact that
        // poll returned success. Let's just do what do as we are told and try
        // again.
        continue;
      }
      return PosixError(errno, "read failed");
    }
    completed += n;
    if (completed >= count) {
      return completed;
    }
  }

  if (completed) {
    return completed;
  }
  return PosixError(ETIMEDOUT, "Poll timed out");
}

TEST(PtyTrunc, Truncate) {
  SKIP_IF(IsRunningWithVFS1());

  // setsid either puts us in a new session or fails because we're already the
  // session leader. Either way, this ensures we're the session leader and have
  // no controlling terminal.
  ASSERT_THAT(setsid(), AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EPERM)));

  // Make sure we're ignoring SIGHUP, which will be sent to this process once we
  // disconnect the TTY.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  const Cleanup cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGHUP, sa));

  // Opening PTYs with O_TRUNC shouldn't cause an error, but calls to
  // (f)truncate should.
  FileDescriptor master =
      ASSERT_NO_ERRNO_AND_VALUE(Open(kMasterPath, O_RDWR | O_TRUNC));
  int n = ASSERT_NO_ERRNO_AND_VALUE(ReplicaID(master));
  std::string spath = absl::StrCat("/dev/pts/", n);
  FileDescriptor replica =
      ASSERT_NO_ERRNO_AND_VALUE(Open(spath, O_RDWR | O_NONBLOCK | O_TRUNC));
  ASSERT_THAT(ioctl(replica.get(), TIOCNOTTY), SyscallSucceeds());

  EXPECT_THAT(truncate(kMasterPath, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(truncate(spath.c_str(), 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(ftruncate(master.get(), 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(ftruncate(replica.get(), 0), SyscallFailsWithErrno(EINVAL));
}

TEST(BasicPtyTest, StatUnopenedMaster) {
  struct stat s;
  ASSERT_THAT(stat(kMasterPath, &s), SyscallSucceeds());

  EXPECT_EQ(s.st_rdev, makedev(TTYAUX_MAJOR, kPtmxMinor));
  EXPECT_EQ(s.st_size, 0);
  EXPECT_EQ(s.st_blocks, 0);

  // ptmx attached to a specific devpts mount uses block size 1024. See
  // fs/devpts/inode.c:devpts_fill_super.
  //
  // The global ptmx device uses the block size of the filesystem it is created
  // on (which is usually 4096 for disk filesystems).
  EXPECT_THAT(s.st_blksize, AnyOf(Eq(1024), Eq(4096)));
}

// Waits for count bytes to be readable from fd. Unlike poll, which can return
// before all data is moved into a pty's read buffer, this function waits for
// all count bytes to become readable.
PosixErrorOr<int> WaitUntilReceived(int fd, int count) {
  int buffered = -1;
  absl::Duration remaining;
  absl::Time end = absl::Now() + kTimeout;
  while ((remaining = end - absl::Now()) > absl::ZeroDuration()) {
    if (ioctl(fd, FIONREAD, &buffered) < 0) {
      return PosixError(errno, "failed FIONREAD ioctl");
    }
    if (buffered >= count) {
      return buffered;
    }
    absl::SleepFor(absl::Milliseconds(500));
  }
  return PosixError(
      ETIMEDOUT,
      absl::StrFormat(
          "FIONREAD timed out, receiving only %d of %d expected bytes",
          buffered, count));
}

// Verifies that there is nothing left to read from fd.
void ExpectFinished(const FileDescriptor& fd) {
  // Nothing more to read.
  char c;
  EXPECT_THAT(ReadFd(fd.get(), &c, 1), SyscallFailsWithErrno(EAGAIN));
}

// Verifies that we can read expected bytes from fd into buf.
void ExpectReadable(const FileDescriptor& fd, int expected, char* buf) {
  size_t n = ASSERT_NO_ERRNO_AND_VALUE(
      PollAndReadFd(fd.get(), buf, expected, kTimeout));
  EXPECT_EQ(expected, n);
}

TEST(BasicPtyTest, OpenMasterReplica) {
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  FileDescriptor replica = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master));
}

TEST(BasicPtyTest, OpenSetsControllingTTY) {
  SKIP_IF(IsRunningWithVFS1());
  // setsid either puts us in a new session or fails because we're already the
  // session leader. Either way, this ensures we're the session leader.
  ASSERT_THAT(setsid(), AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EPERM)));

  // Make sure we're ignoring SIGHUP, which will be sent to this process once we
  // disconnect the TTY.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  struct sigaction old_sa;
  ASSERT_THAT(sigaction(SIGHUP, &sa, &old_sa), SyscallSucceeds());
  auto cleanup = Cleanup([old_sa] {
    EXPECT_THAT(sigaction(SIGHUP, &old_sa, NULL), SyscallSucceeds());
  });

  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  FileDescriptor replica =
      ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master, O_NONBLOCK | O_RDWR));

  // Opening replica should make it our controlling TTY, and therefore we are
  // able to give it up.
  ASSERT_THAT(ioctl(replica.get(), TIOCNOTTY), SyscallSucceeds());
}

TEST(BasicPtyTest, OpenMasterDoesNotSetsControllingTTY) {
  SKIP_IF(IsRunningWithVFS1());
  // setsid either puts us in a new session or fails because we're already the
  // session leader. Either way, this ensures we're the session leader.
  ASSERT_THAT(setsid(), AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EPERM)));
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));

  // Opening master does not set the controlling TTY, and therefore we are
  // unable to give it up.
  ASSERT_THAT(ioctl(master.get(), TIOCNOTTY), SyscallFailsWithErrno(ENOTTY));
}

TEST(BasicPtyTest, OpenNOCTTY) {
  SKIP_IF(IsRunningWithVFS1());
  // setsid either puts us in a new session or fails because we're already the
  // session leader. Either way, this ensures we're the session leader.
  ASSERT_THAT(setsid(), AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EPERM)));
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  FileDescriptor replica = ASSERT_NO_ERRNO_AND_VALUE(
      OpenReplica(master, O_NOCTTY | O_NONBLOCK | O_RDWR));

  // Opening replica with O_NOCTTY won't make it our controlling TTY, and
  // therefore we are unable to give it up.
  ASSERT_THAT(ioctl(replica.get(), TIOCNOTTY), SyscallFailsWithErrno(ENOTTY));
}

// The replica entry in /dev/pts/ disappears when the master is closed, even if
// the replica is still open.
TEST(BasicPtyTest, ReplicaEntryGoneAfterMasterClose) {
  FileDescriptor master = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  FileDescriptor replica = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master));

  // Get pty index.
  int index = -1;
  ASSERT_THAT(ioctl(master.get(), TIOCGPTN, &index), SyscallSucceeds());

  std::string path = absl::StrCat("/dev/pts/", index);

  struct stat st;
  EXPECT_THAT(stat(path.c_str(), &st), SyscallSucceeds());

  master.reset();

  EXPECT_THAT(stat(path.c_str(), &st), SyscallFailsWithErrno(ENOENT));
}

TEST(BasicPtyTest, Getdents) {
  FileDescriptor master1 = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  int index1 = -1;
  ASSERT_THAT(ioctl(master1.get(), TIOCGPTN, &index1), SyscallSucceeds());
  FileDescriptor replica1 = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master1));

  FileDescriptor master2 = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR));
  int index2 = -1;
  ASSERT_THAT(ioctl(master2.get(), TIOCGPTN, &index2), SyscallSucceeds());
  FileDescriptor replica2 = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master2));

  // The directory contains ptmx, index1, and index2. (Plus any additional PTYs
  // unrelated to this test.)

  std::vector<std::string> contents =
      ASSERT_NO_ERRNO_AND_VALUE(ListDir("/dev/pts/", true));
  EXPECT_THAT(contents, Contains(absl::StrCat(index1)));
  EXPECT_THAT(contents, Contains(absl::StrCat(index2)));

  master2.reset();

  // The directory contains ptmx and index1, but not index2 since the master is
  // closed. (Plus any additional PTYs unrelated to this test.)

  contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir("/dev/pts/", true));
  EXPECT_THAT(contents, Contains(absl::StrCat(index1)));
  EXPECT_THAT(contents, Not(Contains(absl::StrCat(index2))));

  // N.B. devpts supports legacy "single-instance" mode and new "multi-instance"
  // mode. In legacy mode, devpts does not contain a "ptmx" device (the distro
  // must use mknod to create it somewhere, presumably /dev/ptmx).
  // Multi-instance mode does include a "ptmx" device tied to that mount.
  //
  // We don't check for the presence or absence of "ptmx", as distros vary in
  // their usage of the two modes.
}

class PtyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    master_ = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR | O_NONBLOCK));
    replica_ = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master_));
  }

  void DisableCanonical() {
    struct kernel_termios t = {};
    EXPECT_THAT(ioctl(replica_.get(), TCGETS, &t), SyscallSucceeds());
    t.c_lflag &= ~ICANON;
    EXPECT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());
  }

  void EnableCanonical() {
    struct kernel_termios t = {};
    EXPECT_THAT(ioctl(replica_.get(), TCGETS, &t), SyscallSucceeds());
    t.c_lflag |= ICANON;
    EXPECT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());
  }

  // Master and replica ends of the PTY. Non-blocking.
  FileDescriptor master_;
  FileDescriptor replica_;
};

// Master to replica sanity test.
TEST_F(PtyTest, WriteMasterToReplica) {
  // N.B. by default, the replica reads nothing until the master writes a
  // newline.
  constexpr char kBuf[] = "hello\n";

  EXPECT_THAT(WriteFd(master_.get(), kBuf, sizeof(kBuf) - 1),
              SyscallSucceedsWithValue(sizeof(kBuf) - 1));

  // Linux moves data from the master to the replica via async work scheduled
  // via tty_flip_buffer_push. Since it is asynchronous, the data may not be
  // available for reading immediately. Instead we must poll and assert that it
  // becomes available "soon".

  char buf[sizeof(kBuf)] = {};
  ExpectReadable(replica_, sizeof(buf) - 1, buf);

  EXPECT_EQ(memcmp(buf, kBuf, sizeof(kBuf)), 0);
}

// Replica to master sanity test.
TEST_F(PtyTest, WriteReplicaToMaster) {
  // N.B. by default, the master reads nothing until the replica writes a
  // newline, and the master gets a carriage return.
  constexpr char kInput[] = "hello\n";
  constexpr char kExpected[] = "hello\r\n";

  EXPECT_THAT(WriteFd(replica_.get(), kInput, sizeof(kInput) - 1),
              SyscallSucceedsWithValue(sizeof(kInput) - 1));

  // Linux moves data from the master to the replica via async work scheduled
  // via tty_flip_buffer_push. Since it is asynchronous, the data may not be
  // available for reading immediately. Instead we must poll and assert that it
  // becomes available "soon".

  char buf[sizeof(kExpected)] = {};
  ExpectReadable(master_, sizeof(buf) - 1, buf);

  EXPECT_EQ(memcmp(buf, kExpected, sizeof(kExpected)), 0);
}

TEST_F(PtyTest, WriteInvalidUTF8) {
  char c = 0xff;
  ASSERT_THAT(syscall(__NR_write, master_.get(), &c, sizeof(c)),
              SyscallSucceedsWithValue(sizeof(c)));
}

// Both the master and replica report the standard default termios settings.
//
// Note that TCGETS on the master actually redirects to the replica (see comment
// on MasterTermiosUnchangable).
TEST_F(PtyTest, DefaultTermios) {
  struct kernel_termios t = {};
  EXPECT_THAT(ioctl(replica_.get(), TCGETS, &t), SyscallSucceeds());
  EXPECT_EQ(t, DefaultTermios());

  EXPECT_THAT(ioctl(master_.get(), TCGETS, &t), SyscallSucceeds());
  EXPECT_EQ(t, DefaultTermios());
}

// Changing termios from the master actually affects the replica.
//
// TCSETS on the master actually redirects to the replica (see comment on
// MasterTermiosUnchangable).
TEST_F(PtyTest, TermiosAffectsReplica) {
  struct kernel_termios master_termios = {};
  EXPECT_THAT(ioctl(master_.get(), TCGETS, &master_termios), SyscallSucceeds());
  master_termios.c_lflag ^= ICANON;
  EXPECT_THAT(ioctl(master_.get(), TCSETS, &master_termios), SyscallSucceeds());

  struct kernel_termios replica_termios = {};
  EXPECT_THAT(ioctl(replica_.get(), TCGETS, &replica_termios),
              SyscallSucceeds());
  EXPECT_EQ(master_termios, replica_termios);
}

// The master end of the pty has termios:
//
// struct kernel_termios t = {
//   .c_iflag = 0;
//   .c_oflag = 0;
//   .c_cflag = B38400 | CS8 | CREAD;
//   .c_lflag = 0;
//   .c_cc = /* same as DefaultTermios */
// }
//
// (From drivers/tty/pty.c:unix98_pty_init)
//
// All termios control ioctls on the master actually redirect to the replica
// (drivers/tty/tty_ioctl.c:tty_mode_ioctl), making it impossible to change the
// master termios.
//
// Verify this by setting ICRNL (which rewrites input \r to \n) and verify that
// it has no effect on the master.
TEST_F(PtyTest, MasterTermiosUnchangable) {
  struct kernel_termios master_termios = {};
  EXPECT_THAT(ioctl(master_.get(), TCGETS, &master_termios), SyscallSucceeds());
  master_termios.c_lflag |= ICRNL;
  EXPECT_THAT(ioctl(master_.get(), TCSETS, &master_termios), SyscallSucceeds());

  char c = '\r';
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  ExpectReadable(master_, 1, &c);
  EXPECT_EQ(c, '\r');  // ICRNL had no effect!

  ExpectFinished(master_);
}

// ICRNL rewrites input \r to \n.
TEST_F(PtyTest, TermiosICRNL) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= ICRNL;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  char c = '\r';
  ASSERT_THAT(WriteFd(master_.get(), &c, 1), SyscallSucceedsWithValue(1));

  ExpectReadable(replica_, 1, &c);
  EXPECT_EQ(c, '\n');

  ExpectFinished(replica_);
}

// ONLCR rewrites output \n to \r\n.
TEST_F(PtyTest, TermiosONLCR) {
  struct kernel_termios t = DefaultTermios();
  t.c_oflag |= ONLCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  char c = '\n';
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  // Extra byte for NUL for EXPECT_STREQ.
  char buf[3] = {};
  ExpectReadable(master_, 2, buf);
  EXPECT_STREQ(buf, "\r\n");

  ExpectFinished(replica_);
}

TEST_F(PtyTest, TermiosIGNCR) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= IGNCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  char c = '\r';
  ASSERT_THAT(WriteFd(master_.get(), &c, 1), SyscallSucceedsWithValue(1));

  // Nothing to read.
  ASSERT_THAT(PollAndReadFd(replica_.get(), &c, 1, kTimeout),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));
}

// Test that we can successfully poll for readable data from the replica.
TEST_F(PtyTest, TermiosPollReplica) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= IGNCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  absl::Notification notify;
  int sfd = replica_.get();
  ScopedThread th([sfd, &notify]() {
    notify.Notify();

    // Poll on the reader fd with POLLIN event.
    struct pollfd poll_fd = {sfd, POLLIN, 0};
    EXPECT_THAT(
        RetryEINTR(poll)(&poll_fd, 1, absl::ToInt64Milliseconds(kTimeout)),
        SyscallSucceedsWithValue(1));

    // Should trigger POLLIN event.
    EXPECT_EQ(poll_fd.revents & POLLIN, POLLIN);
  });

  notify.WaitForNotification();
  // Sleep ensures that poll begins waiting before we write to the FD.
  absl::SleepFor(absl::Seconds(1));

  char s[] = "foo\n";
  ASSERT_THAT(WriteFd(master_.get(), s, strlen(s) + 1), SyscallSucceeds());
}

// Test that we can successfully poll for readable data from the master.
TEST_F(PtyTest, TermiosPollMaster) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= IGNCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(master_.get(), TCSETS, &t), SyscallSucceeds());

  absl::Notification notify;
  int mfd = master_.get();
  ScopedThread th([mfd, &notify]() {
    notify.Notify();

    // Poll on the reader fd with POLLIN event.
    struct pollfd poll_fd = {mfd, POLLIN, 0};
    EXPECT_THAT(
        RetryEINTR(poll)(&poll_fd, 1, absl::ToInt64Milliseconds(kTimeout)),
        SyscallSucceedsWithValue(1));

    // Should trigger POLLIN event.
    EXPECT_EQ(poll_fd.revents & POLLIN, POLLIN);
  });

  notify.WaitForNotification();
  // Sleep ensures that poll begins waiting before we write to the FD.
  absl::SleepFor(absl::Seconds(1));

  char s[] = "foo\n";
  ASSERT_THAT(WriteFd(replica_.get(), s, strlen(s) + 1), SyscallSucceeds());
}

TEST_F(PtyTest, TermiosINLCR) {
  struct kernel_termios t = DefaultTermios();
  t.c_iflag |= INLCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  char c = '\n';
  ASSERT_THAT(WriteFd(master_.get(), &c, 1), SyscallSucceedsWithValue(1));

  ExpectReadable(replica_, 1, &c);
  EXPECT_EQ(c, '\r');

  ExpectFinished(replica_);
}

TEST_F(PtyTest, TermiosONOCR) {
  struct kernel_termios t = DefaultTermios();
  t.c_oflag |= ONOCR;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  // The terminal is at column 0, so there should be no CR to read.
  char c = '\r';
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  // Nothing to read.
  ASSERT_THAT(PollAndReadFd(master_.get(), &c, 1, kTimeout),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));

  // This time the column is greater than 0, so we should be able to read the CR
  // out of the other end.
  constexpr char kInput[] = "foo\r";
  constexpr int kInputSize = sizeof(kInput) - 1;
  ASSERT_THAT(WriteFd(replica_.get(), kInput, kInputSize),
              SyscallSucceedsWithValue(kInputSize));

  char buf[kInputSize] = {};
  ExpectReadable(master_, kInputSize, buf);

  EXPECT_EQ(memcmp(buf, kInput, kInputSize), 0);

  ExpectFinished(master_);

  // Terminal should be at column 0 again, so no CR can be read.
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  // Nothing to read.
  ASSERT_THAT(PollAndReadFd(master_.get(), &c, 1, kTimeout),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));
}

TEST_F(PtyTest, TermiosOCRNL) {
  struct kernel_termios t = DefaultTermios();
  t.c_oflag |= OCRNL;
  t.c_lflag &= ~ICANON;  // for byte-by-byte reading.
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());

  // The terminal is at column 0, so there should be no CR to read.
  char c = '\r';
  ASSERT_THAT(WriteFd(replica_.get(), &c, 1), SyscallSucceedsWithValue(1));

  ExpectReadable(master_, 1, &c);
  EXPECT_EQ(c, '\n');

  ExpectFinished(master_);
}

// Tests that VEOL is disabled when we start, and that we can set it to enable
// it.
TEST_F(PtyTest, VEOLTermination) {
  // Write a few bytes ending with '\0', and confirm that we can't read.
  constexpr char kInput[] = "hello";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));
  char buf[sizeof(kInput)] = {};
  ASSERT_THAT(PollAndReadFd(replica_.get(), buf, sizeof(kInput), kTimeout),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));

  // Set the EOL character to '=' and write it.
  constexpr char delim = '=';
  struct kernel_termios t = DefaultTermios();
  t.c_cc[VEOL] = delim;
  ASSERT_THAT(ioctl(replica_.get(), TCSETS, &t), SyscallSucceeds());
  ASSERT_THAT(WriteFd(master_.get(), &delim, 1), SyscallSucceedsWithValue(1));

  // Now we can read, as sending EOL caused the line to become available.
  ExpectReadable(replica_, sizeof(kInput), buf);
  EXPECT_EQ(memcmp(buf, kInput, sizeof(kInput)), 0);

  ExpectReadable(replica_, 1, buf);
  EXPECT_EQ(buf[0], '=');

  ExpectFinished(replica_);
}

// Tests that we can write more than the 4096 character limit, then a
// terminating character, then read out just the first 4095 bytes plus the
// terminator.
TEST_F(PtyTest, CanonBigWrite) {
  constexpr int kWriteLen = kMaxLineSize + 4;
  char input[kWriteLen];
  memset(input, 'M', kWriteLen - 1);
  input[kWriteLen - 1] = '\n';
  ASSERT_THAT(WriteFd(master_.get(), input, kWriteLen),
              SyscallSucceedsWithValue(kWriteLen));

  // We can read the line.
  char buf[kMaxLineSize] = {};
  ExpectReadable(replica_, kMaxLineSize, buf);

  ExpectFinished(replica_);
}

// Tests that data written in canonical mode can be read immediately once
// switched to noncanonical mode.
TEST_F(PtyTest, SwitchCanonToNoncanon) {
  // Write a few bytes without a terminating character, switch to noncanonical
  // mode, and read them.
  constexpr char kInput[] = "hello";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));

  // Nothing available yet.
  char buf[sizeof(kInput)] = {};
  ASSERT_THAT(PollAndReadFd(replica_.get(), buf, sizeof(kInput), kTimeout),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));

  DisableCanonical();

  ExpectReadable(replica_, sizeof(kInput), buf);
  EXPECT_STREQ(buf, kInput);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchCanonToNonCanonNewline) {
  // Write a few bytes with a terminating character.
  constexpr char kInput[] = "hello\n";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));

  DisableCanonical();

  // We can read the line.
  char buf[sizeof(kInput)] = {};
  ExpectReadable(replica_, sizeof(kInput), buf);
  EXPECT_STREQ(buf, kInput);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchNoncanonToCanonNewlineBig) {
  DisableCanonical();

  // Write more than the maximum line size, then write a delimiter.
  constexpr int kWriteLen = 4100;
  char input[kWriteLen];
  memset(input, 'M', kWriteLen);
  ASSERT_THAT(WriteFd(master_.get(), input, kWriteLen),
              SyscallSucceedsWithValue(kWriteLen));
  // Wait for the input queue to fill.
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), kMaxLineSize - 1));
  constexpr char delim = '\n';
  ASSERT_THAT(WriteFd(master_.get(), &delim, 1), SyscallSucceedsWithValue(1));

  EnableCanonical();

  // We can read the line.
  char buf[kMaxLineSize] = {};
  ExpectReadable(replica_, kMaxLineSize - 1, buf);

  // We can also read the remaining characters.
  ExpectReadable(replica_, 6, buf);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchNoncanonToCanonNoNewline) {
  DisableCanonical();

  // Write a few bytes without a terminating character.
  // mode, and read them.
  constexpr char kInput[] = "hello";
  ASSERT_THAT(WriteFd(master_.get(), kInput, sizeof(kInput) - 1),
              SyscallSucceedsWithValue(sizeof(kInput) - 1));

  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), sizeof(kInput) - 1));
  EnableCanonical();

  // We can read the line.
  char buf[sizeof(kInput)] = {};
  ExpectReadable(replica_, sizeof(kInput) - 1, buf);
  EXPECT_STREQ(buf, kInput);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchNoncanonToCanonNoNewlineBig) {
  DisableCanonical();

  // Write a few bytes without a terminating character.
  // mode, and read them.
  constexpr int kWriteLen = 4100;
  char input[kWriteLen];
  memset(input, 'M', kWriteLen);
  ASSERT_THAT(WriteFd(master_.get(), input, kWriteLen),
              SyscallSucceedsWithValue(kWriteLen));

  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), kMaxLineSize - 1));
  EnableCanonical();

  // We can read the line.
  char buf[kMaxLineSize] = {};
  ExpectReadable(replica_, kMaxLineSize - 1, buf);

  ExpectFinished(replica_);
}

// Tests that we can write over the 4095 noncanonical limit, then read out
// everything.
TEST_F(PtyTest, NoncanonBigWrite) {
  DisableCanonical();

  // Write well over the 4095 internal buffer limit.
  constexpr char kInput = 'M';
  constexpr int kInputSize = kMaxLineSize * 2;
  for (int i = 0; i < kInputSize; i++) {
    // This makes too many syscalls for save/restore.
    const DisableSave ds;
    ASSERT_THAT(WriteFd(master_.get(), &kInput, sizeof(kInput)),
                SyscallSucceedsWithValue(sizeof(kInput)));
  }

  // We should be able to read out everything. Sleep a bit so that Linux has a
  // chance to move data from the master to the replica.
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), kMaxLineSize - 1));
  for (int i = 0; i < kInputSize; i++) {
    // This makes too many syscalls for save/restore.
    const DisableSave ds;
    char c;
    ExpectReadable(replica_, 1, &c);
    ASSERT_EQ(c, kInput);
  }

  ExpectFinished(replica_);
}

// ICANON doesn't make input available until a line delimiter is typed.
//
// Test newline.
TEST_F(PtyTest, TermiosICANONNewline) {
  char input[3] = {'a', 'b', 'c'};
  ASSERT_THAT(WriteFd(master_.get(), input, sizeof(input)),
              SyscallSucceedsWithValue(sizeof(input)));

  // Extra bytes for newline (written later) and NUL for EXPECT_STREQ.
  char buf[5] = {};

  // Nothing available yet.
  ASSERT_THAT(PollAndReadFd(replica_.get(), buf, sizeof(input), kTimeout),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));

  char delim = '\n';
  ASSERT_THAT(WriteFd(master_.get(), &delim, 1), SyscallSucceedsWithValue(1));

  // Now it is available.
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), sizeof(input) + 1));
  ExpectReadable(replica_, sizeof(input) + 1, buf);
  EXPECT_STREQ(buf, "abc\n");

  ExpectFinished(replica_);
}

// ICANON doesn't make input available until a line delimiter is typed.
//
// Test EOF (^D).
TEST_F(PtyTest, TermiosICANONEOF) {
  char input[3] = {'a', 'b', 'c'};
  ASSERT_THAT(WriteFd(master_.get(), input, sizeof(input)),
              SyscallSucceedsWithValue(sizeof(input)));

  // Extra byte for NUL for EXPECT_STREQ.
  char buf[4] = {};

  // Nothing available yet.
  ASSERT_THAT(PollAndReadFd(replica_.get(), buf, sizeof(input), kTimeout),
              PosixErrorIs(ETIMEDOUT, ::testing::StrEq("Poll timed out")));
  char delim = ControlCharacter('D');
  ASSERT_THAT(WriteFd(master_.get(), &delim, 1), SyscallSucceedsWithValue(1));

  // Now it is available. Note that ^D is not included.
  ExpectReadable(replica_, sizeof(input), buf);
  EXPECT_STREQ(buf, "abc");

  ExpectFinished(replica_);
}

// ICANON limits us to 4096 bytes including a terminating character. Anything
// after and 4095th character is discarded (although still processed for
// signals and echoing).
TEST_F(PtyTest, CanonDiscard) {
  constexpr char kInput = 'M';
  constexpr int kInputSize = 4100;
  constexpr int kIter = 3;

  // A few times write more than the 4096 character maximum, then a newline.
  constexpr char delim = '\n';
  for (int i = 0; i < kIter; i++) {
    // This makes too many syscalls for save/restore.
    const DisableSave ds;
    for (int i = 0; i < kInputSize; i++) {
      ASSERT_THAT(WriteFd(master_.get(), &kInput, sizeof(kInput)),
                  SyscallSucceedsWithValue(sizeof(kInput)));
    }
    ASSERT_THAT(WriteFd(master_.get(), &delim, 1), SyscallSucceedsWithValue(1));
  }

  // There should be multiple truncated lines available to read.
  for (int i = 0; i < kIter; i++) {
    char buf[kInputSize] = {};
    ExpectReadable(replica_, kMaxLineSize, buf);
    EXPECT_EQ(buf[kMaxLineSize - 1], delim);
    EXPECT_EQ(buf[kMaxLineSize - 2], kInput);
  }

  ExpectFinished(replica_);
}

TEST_F(PtyTest, CanonMultiline) {
  constexpr char kInput1[] = "GO\n";
  constexpr char kInput2[] = "BLUE\n";

  // Write both lines.
  ASSERT_THAT(WriteFd(master_.get(), kInput1, sizeof(kInput1) - 1),
              SyscallSucceedsWithValue(sizeof(kInput1) - 1));
  ASSERT_THAT(WriteFd(master_.get(), kInput2, sizeof(kInput2) - 1),
              SyscallSucceedsWithValue(sizeof(kInput2) - 1));

  // Get the first line.
  char line1[8] = {};
  ExpectReadable(replica_, sizeof(kInput1) - 1, line1);
  EXPECT_STREQ(line1, kInput1);

  // Get the second line.
  char line2[8] = {};
  ExpectReadable(replica_, sizeof(kInput2) - 1, line2);
  EXPECT_STREQ(line2, kInput2);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchNoncanonToCanonMultiline) {
  DisableCanonical();

  constexpr char kInput1[] = "GO\n";
  constexpr char kInput2[] = "BLUE\n";
  constexpr char kExpected[] = "GO\nBLUE\n";

  // Write both lines.
  ASSERT_THAT(WriteFd(master_.get(), kInput1, sizeof(kInput1) - 1),
              SyscallSucceedsWithValue(sizeof(kInput1) - 1));
  ASSERT_THAT(WriteFd(master_.get(), kInput2, sizeof(kInput2) - 1),
              SyscallSucceedsWithValue(sizeof(kInput2) - 1));

  ASSERT_NO_ERRNO(
      WaitUntilReceived(replica_.get(), sizeof(kInput1) + sizeof(kInput2) - 2));
  EnableCanonical();

  // Get all together as one line.
  char line[9] = {};
  ExpectReadable(replica_, 8, line);
  EXPECT_STREQ(line, kExpected);

  ExpectFinished(replica_);
}

TEST_F(PtyTest, SwitchTwiceMultiline) {
  std::string kInputs[] = {"GO\n", "BLUE\n", "!"};
  std::string kExpected = "GO\nBLUE\n!";

  // Write each line.
  for (const std::string& input : kInputs) {
    ASSERT_THAT(WriteFd(master_.get(), input.c_str(), input.size()),
                SyscallSucceedsWithValue(input.size()));
  }

  DisableCanonical();
  // All written characters have to make it into the input queue before
  // canonical mode is re-enabled. If the final '!' character hasn't been
  // enqueued before canonical mode is re-enabled, it won't be readable.
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), kExpected.size()));
  EnableCanonical();

  // Get all together as one line.
  char line[10] = {};
  ExpectReadable(replica_, 9, line);
  EXPECT_STREQ(line, kExpected.c_str());

  ExpectFinished(replica_);
}

TEST_F(PtyTest, QueueSize) {
  // Write the line.
  constexpr char kInput1[] = "GO\n";
  ASSERT_THAT(WriteFd(master_.get(), kInput1, sizeof(kInput1) - 1),
              SyscallSucceedsWithValue(sizeof(kInput1) - 1));
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), sizeof(kInput1) - 1));

  // Ensure that writing more (beyond what is readable) does not impact the
  // readable size.
  char input[kMaxLineSize];
  memset(input, 'M', kMaxLineSize);
  ASSERT_THAT(WriteFd(master_.get(), input, kMaxLineSize),
              SyscallSucceedsWithValue(kMaxLineSize));
  int inputBufSize = ASSERT_NO_ERRNO_AND_VALUE(
      WaitUntilReceived(replica_.get(), sizeof(kInput1) - 1));
  EXPECT_EQ(inputBufSize, sizeof(kInput1) - 1);
}

TEST_F(PtyTest, PartialBadBuffer) {
  // Allocate 2 pages.
  void* addr = mmap(nullptr, 2 * kPageSize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(addr, MAP_FAILED);
  char* buf = reinterpret_cast<char*>(addr);

  // Guard the 2nd page for our read to run into.
  ASSERT_THAT(
      mprotect(reinterpret_cast<void*>(buf + kPageSize), kPageSize, PROT_NONE),
      SyscallSucceeds());

  // Leave only one free byte in the buffer.
  char* bad_buffer = buf + kPageSize - 1;

  // Write to the master.
  constexpr char kBuf[] = "hello\n";
  constexpr size_t size = sizeof(kBuf) - 1;
  EXPECT_THAT(WriteFd(master_.get(), kBuf, size),
              SyscallSucceedsWithValue(size));

  // Read from the replica into bad_buffer.
  ASSERT_NO_ERRNO(WaitUntilReceived(replica_.get(), size));
  // Before Linux 3b830a9c this returned EFAULT, but after that commit it
  // returns EAGAIN.
  EXPECT_THAT(
      ReadFd(replica_.get(), bad_buffer, size),
      AnyOf(SyscallFailsWithErrno(EFAULT), SyscallFailsWithErrno(EAGAIN)));

  EXPECT_THAT(munmap(addr, 2 * kPageSize), SyscallSucceeds()) << addr;
}

TEST_F(PtyTest, SimpleEcho) {
  constexpr char kInput[] = "Mr. Eko";
  EXPECT_THAT(WriteFd(master_.get(), kInput, strlen(kInput)),
              SyscallSucceedsWithValue(strlen(kInput)));

  char buf[100] = {};
  ExpectReadable(master_, strlen(kInput), buf);

  EXPECT_STREQ(buf, kInput);
  ExpectFinished(master_);
}

TEST_F(PtyTest, GetWindowSize) {
  struct winsize ws;
  ASSERT_THAT(ioctl(replica_.get(), TIOCGWINSZ, &ws), SyscallSucceeds());
  EXPECT_EQ(ws.ws_row, 0);
  EXPECT_EQ(ws.ws_col, 0);
}

TEST_F(PtyTest, SetReplicaWindowSize) {
  constexpr uint16_t kRows = 343;
  constexpr uint16_t kCols = 2401;
  struct winsize ws = {.ws_row = kRows, .ws_col = kCols};
  ASSERT_THAT(ioctl(replica_.get(), TIOCSWINSZ, &ws), SyscallSucceeds());

  struct winsize retrieved_ws = {};
  ASSERT_THAT(ioctl(master_.get(), TIOCGWINSZ, &retrieved_ws),
              SyscallSucceeds());
  EXPECT_EQ(retrieved_ws.ws_row, kRows);
  EXPECT_EQ(retrieved_ws.ws_col, kCols);
}

TEST_F(PtyTest, SetMasterWindowSize) {
  constexpr uint16_t kRows = 343;
  constexpr uint16_t kCols = 2401;
  struct winsize ws = {.ws_row = kRows, .ws_col = kCols};
  ASSERT_THAT(ioctl(master_.get(), TIOCSWINSZ, &ws), SyscallSucceeds());

  struct winsize retrieved_ws = {};
  ASSERT_THAT(ioctl(replica_.get(), TIOCGWINSZ, &retrieved_ws),
              SyscallSucceeds());
  EXPECT_EQ(retrieved_ws.ws_row, kRows);
  EXPECT_EQ(retrieved_ws.ws_col, kCols);
}

class JobControlTest : public ::testing::Test {
 protected:
  void SetUp() override {
    master_ = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/ptmx", O_RDWR | O_NONBLOCK));
    replica_ = ASSERT_NO_ERRNO_AND_VALUE(OpenReplica(master_));

    // Make this a session leader, which also drops the controlling terminal.
    // In the gVisor test environment, this test will be run as the session
    // leader already (as the sentry init process).
    if (!IsRunningOnGvisor()) {
      // Ignore failure because setsid(2) fails if the process is already the
      // session leader.
      setsid();
      ioctl(replica_.get(), TIOCNOTTY);
    }
  }

  PosixError RunInChild(SubprocessCallback childFunc) {
    pid_t child = fork();
    if (!child) {
      childFunc();
      _exit(0);
    }
    int wstatus;
    if (waitpid(child, &wstatus, 0) != child) {
      return PosixError(
          errno, absl::StrCat("child failed with wait status: ", wstatus));
    }
    return PosixError(wstatus, "process returned");
  }

  // Master and replica ends of the PTY. Non-blocking.
  FileDescriptor master_;
  FileDescriptor replica_;
};

TEST_F(JobControlTest, SetTTYMaster) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(master_.get(), TIOCSCTTY, 0));
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetTTY) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(ioctl(!replica_.get(), TIOCSCTTY, 0));
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetTTYNonLeader) {
  // Fork a process that won't be the session leader.
  auto res =
      RunInChild([=]() { TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 0)); });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetTTYBadArg) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 1));
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetTTYDifferentSession) {
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 1));

    // Fork, join a new session, and try to steal the parent's controlling
    // terminal, which should fail.
    pid_t grandchild = fork();
    if (!grandchild) {
      TEST_PCHECK(setsid() >= 0);
      // We shouldn't be able to steal the terminal.
      TEST_PCHECK(ioctl(replica_.get(), TIOCSCTTY, 1));
      _exit(0);
    }

    int gcwstatus;
    TEST_PCHECK(waitpid(grandchild, &gcwstatus, 0) == grandchild);
    TEST_PCHECK(gcwstatus == 0);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, ReleaseTTY) {
  ASSERT_THAT(ioctl(replica_.get(), TIOCSCTTY, 0), SyscallSucceeds());

  // Make sure we're ignoring SIGHUP, which will be sent to this process once we
  // disconnect the TTY.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  struct sigaction old_sa;
  EXPECT_THAT(sigaction(SIGHUP, &sa, &old_sa), SyscallSucceeds());
  EXPECT_THAT(ioctl(replica_.get(), TIOCNOTTY), SyscallSucceeds());
  EXPECT_THAT(sigaction(SIGHUP, &old_sa, NULL), SyscallSucceeds());
}

TEST_F(JobControlTest, ReleaseUnsetTTY) {
  ASSERT_THAT(ioctl(replica_.get(), TIOCNOTTY), SyscallFailsWithErrno(ENOTTY));
}

TEST_F(JobControlTest, ReleaseWrongTTY) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));
    TEST_PCHECK(ioctl(master_.get(), TIOCNOTTY) < 0 && errno == ENOTTY);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, ReleaseTTYNonLeader) {
  auto ret = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    pid_t grandchild = fork();
    if (!grandchild) {
      TEST_PCHECK(!ioctl(replica_.get(), TIOCNOTTY));
      _exit(0);
    }

    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, 0) == grandchild);
    TEST_PCHECK(wstatus == 0);
  });
  ASSERT_NO_ERRNO(ret);
}

TEST_F(JobControlTest, ReleaseTTYDifferentSession) {
  auto ret = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);

    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    pid_t grandchild = fork();
    if (!grandchild) {
      // Join a new session, then try to disconnect.
      TEST_PCHECK(setsid() >= 0);
      TEST_PCHECK(ioctl(replica_.get(), TIOCNOTTY));
      _exit(0);
    }

    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, 0) == grandchild);
    TEST_PCHECK(wstatus == 0);
  });
  ASSERT_NO_ERRNO(ret);
}

// Used by the child process spawned in ReleaseTTYSignals to track received
// signals.
static int received;

void sig_handler(int signum) { received |= signum; }

// When the session leader releases its controlling terminal, the foreground
// process group gets SIGHUP, then SIGCONT. This test:
// - Spawns 2 threads
// - Has thread 1 return 0 if it gets both SIGHUP and SIGCONT
// - Has thread 2 leave the foreground process group, and return non-zero if it
//   receives any signals.
// - Has the parent thread release its controlling terminal
// - Checks that thread 1 got both signals
// - Checks that thread 2 didn't get any signals.
TEST_F(JobControlTest, ReleaseTTYSignals) {
  ASSERT_THAT(ioctl(replica_.get(), TIOCSCTTY, 0), SyscallSucceeds());

  received = 0;
  struct sigaction sa = {};
  sa.sa_handler = sig_handler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGHUP);
  sigaddset(&sa.sa_mask, SIGCONT);
  sigprocmask(SIG_BLOCK, &sa.sa_mask, NULL);

  pid_t same_pgrp_child = fork();
  if (!same_pgrp_child) {
    // The child will wait for SIGHUP and SIGCONT, then return 0. It begins with
    // SIGHUP and SIGCONT blocked. We install signal handlers for those signals,
    // then use sigsuspend to wait for those specific signals.
    TEST_PCHECK(!sigaction(SIGHUP, &sa, NULL));
    TEST_PCHECK(!sigaction(SIGCONT, &sa, NULL));
    sigset_t mask;
    sigfillset(&mask);
    sigdelset(&mask, SIGHUP);
    sigdelset(&mask, SIGCONT);
    while (received != (SIGHUP | SIGCONT)) {
      sigsuspend(&mask);
    }
    _exit(0);
  }

  // We don't want to block these anymore.
  sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL);

  // This child will return non-zero if either SIGHUP or SIGCONT are received.
  pid_t diff_pgrp_child = fork();
  if (!diff_pgrp_child) {
    TEST_PCHECK(!setpgid(0, 0));
    TEST_PCHECK(pause());
    _exit(1);
  }

  EXPECT_THAT(setpgid(diff_pgrp_child, diff_pgrp_child), SyscallSucceeds());

  // Make sure we're ignoring SIGHUP, which will be sent to this process once we
  // disconnect the TTY.
  struct sigaction sighup_sa = {};
  sighup_sa.sa_handler = SIG_IGN;
  sighup_sa.sa_flags = 0;
  sigemptyset(&sighup_sa.sa_mask);
  struct sigaction old_sa;
  EXPECT_THAT(sigaction(SIGHUP, &sighup_sa, &old_sa), SyscallSucceeds());

  // Release the controlling terminal, sending SIGHUP and SIGCONT to all other
  // processes in this process group.
  EXPECT_THAT(ioctl(replica_.get(), TIOCNOTTY), SyscallSucceeds());

  EXPECT_THAT(sigaction(SIGHUP, &old_sa, NULL), SyscallSucceeds());

  // The child in the same process group will get signaled.
  int wstatus;
  EXPECT_THAT(waitpid(same_pgrp_child, &wstatus, 0),
              SyscallSucceedsWithValue(same_pgrp_child));
  EXPECT_EQ(wstatus, 0);

  // The other child will not get signaled.
  EXPECT_THAT(waitpid(diff_pgrp_child, &wstatus, WNOHANG),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(kill(diff_pgrp_child, SIGKILL), SyscallSucceeds());
}

TEST_F(JobControlTest, GetForegroundProcessGroup) {
  auto res = RunInChild([=]() {
    pid_t pid, foreground_pgid;
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 1));
    TEST_PCHECK(!ioctl(replica_.get(), TIOCGPGRP, &foreground_pgid));
    TEST_PCHECK((pid = getpid()) >= 0);
    TEST_PCHECK(pid == foreground_pgid);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, GetForegroundProcessGroupNonControlling) {
  // At this point there's no controlling terminal, so TIOCGPGRP should fail.
  pid_t foreground_pgid;
  ASSERT_THAT(ioctl(replica_.get(), TIOCGPGRP, &foreground_pgid),
              SyscallFailsWithErrno(ENOTTY));
}

// This test:
// - sets itself as the foreground process group
// - creates a child process in a new process group
// - sets that child as the foreground process group
// - kills its child and sets itself as the foreground process group.
// TODO(gvisor.dev/issue/5357): Fix and enable.
TEST_F(JobControlTest, DISABLED_SetForegroundProcessGroup) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    // Ignore SIGTTOU so that we don't stop ourself when calling tcsetpgrp.
    struct sigaction sa = {};
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTTOU, &sa, NULL);

    // Set ourself as the foreground process group.
    TEST_PCHECK(!tcsetpgrp(replica_.get(), getpgid(0)));

    // Create a new process that just waits to be signaled.
    pid_t grandchild = fork();
    if (!grandchild) {
      TEST_PCHECK(!pause());
      // We should never reach this.
      _exit(1);
    }

    // Make the child its own process group, then make it the controlling
    // process group of the terminal.
    TEST_PCHECK(!setpgid(grandchild, grandchild));
    TEST_PCHECK(!tcsetpgrp(replica_.get(), grandchild));

    // Sanity check - we're still the controlling session.
    TEST_PCHECK(getsid(0) == getsid(grandchild));

    // Signal the child, wait for it to exit, then retake the terminal.
    TEST_PCHECK(!kill(grandchild, SIGTERM));
    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, 0) == grandchild);
    TEST_PCHECK(WIFSIGNALED(wstatus));
    TEST_PCHECK(WTERMSIG(wstatus) == SIGTERM);

    // Set ourself as the foreground process.
    pid_t pgid;
    TEST_PCHECK(pgid = getpgid(0) == 0);
    TEST_PCHECK(!tcsetpgrp(replica_.get(), pgid));
  });
  ASSERT_NO_ERRNO(res);
}

// This test verifies if a SIGTTOU signal is sent to the calling process's group
// when tcsetpgrp is called by a background process
TEST_F(JobControlTest, SetForegroundProcessGroupSIGTTOUBackground) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));
    pid_t grandchild = fork();
    if (!grandchild) {
      // Assign a different pgid to the child so it will result as
      // a background process.
      TEST_PCHECK(!setpgid(grandchild, getpid()));
      TEST_PCHECK(!tcsetpgrp(replica_.get(), getpgid(0)));
      // We should never reach this.
      _exit(1);
    }
    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, WSTOPPED) == grandchild);
    TEST_PCHECK(WSTOPSIG(wstatus) == SIGTTOU);
  });
  ASSERT_NO_ERRNO(res);
}

// This test verifies that a SIGTTOU signal is not delivered to
// a background process which calls tcsetpgrp and is ignoring SIGTTOU
TEST_F(JobControlTest, SetForegroundProcessGroupSIGTTOUIgnored) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));
    pid_t grandchild = fork();
    if (!grandchild) {
      // Ignore SIGTTOU so the child in background won't
      // be stopped when it will call tcsetpgrp
      struct sigaction sa = {};
      sa.sa_handler = SIG_IGN;
      sa.sa_flags = 0;
      sigemptyset(&sa.sa_mask);
      sigaction(SIGTTOU, &sa, NULL);
      // Assign a different pgid to the child so it will result as
      // a background process.
      TEST_PCHECK(!setpgid(grandchild, getpid()));
      TEST_PCHECK(!tcsetpgrp(replica_.get(), getpgid(0)));
      _exit(0);
    }
    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, WSTOPPED) == grandchild);
    TEST_PCHECK(WSTOPSIG(wstatus) != SIGTTOU);
    TEST_PCHECK(WIFEXITED(wstatus));
  });
  ASSERT_NO_ERRNO(res);
}

// This test verifies that a SIGTTOU signal is not delivered to
// a background process which calls tcsetpgrp and is blocking SIGTTOU
TEST_F(JobControlTest, SetForegroundProcessGroupSIGTTOUBlocked) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));
    pid_t grandchild = fork();
    if (!grandchild) {
      // Block SIGTTOU so the child in background won't
      // be stopped when it will call tcsetpgrp
      sigset_t signal_set;
      sigemptyset(&signal_set);
      sigaddset(&signal_set, SIGTTOU);
      sigprocmask(SIG_BLOCK, &signal_set, NULL);
      // Assign a different pgid to the child so it will result as
      // a background process.
      TEST_PCHECK(!setpgid(grandchild, getpid()));
      TEST_PCHECK(!tcsetpgrp(replica_.get(), getpgid(0)));
      _exit(0);
    }
    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, WSTOPPED) == grandchild);
    TEST_PCHECK(WSTOPSIG(wstatus) != SIGTTOU);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetForegroundProcessGroupWrongTTY) {
  pid_t pid = getpid();
  ASSERT_THAT(ioctl(replica_.get(), TIOCSPGRP, &pid),
              SyscallFailsWithErrno(ENOTTY));
}

TEST_F(JobControlTest, SetForegroundProcessGroupNegPgid) {
  auto ret = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    pid_t pid = -1;
    TEST_PCHECK(ioctl(replica_.get(), TIOCSPGRP, &pid) && errno == EINVAL);
  });
  ASSERT_NO_ERRNO(ret);
}

// TODO(gvisor.dev/issue/5357): Fix and enable.
TEST_F(JobControlTest, DISABLED_SetForegroundProcessGroupEmptyProcessGroup) {
  auto res = RunInChild([=]() {
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    // Create a new process, put it in a new process group, make that group the
    // foreground process group, then have the process wait.
    pid_t grandchild = fork();
    if (!grandchild) {
      TEST_PCHECK(!setpgid(0, 0));
      _exit(0);
    }

    // Wait for the child to exit.
    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, 0) == grandchild);
    // The child's process group doesn't exist anymore - this should fail.
    TEST_PCHECK(ioctl(replica_.get(), TIOCSPGRP, &grandchild) != 0 &&
                errno == ESRCH);
  });
  ASSERT_NO_ERRNO(res);
}

TEST_F(JobControlTest, SetForegroundProcessGroupDifferentSession) {
  auto ret = RunInChild([=]() {
    TEST_PCHECK(setsid() >= 0);
    TEST_PCHECK(!ioctl(replica_.get(), TIOCSCTTY, 0));

    int sync_setsid[2];
    int sync_exit[2];
    TEST_PCHECK(pipe(sync_setsid) >= 0);
    TEST_PCHECK(pipe(sync_exit) >= 0);

    // Create a new process and put it in a new session.
    pid_t grandchild = fork();
    if (!grandchild) {
      TEST_PCHECK(setsid() >= 0);
      // Tell the parent we're in a new session.
      char c = 'c';
      TEST_PCHECK(WriteFd(sync_setsid[1], &c, 1) == 1);
      TEST_PCHECK(ReadFd(sync_exit[0], &c, 1) == 1);
      _exit(0);
    }

    // Wait for the child to tell us it's in a new session.
    char c = 'c';
    TEST_PCHECK(ReadFd(sync_setsid[0], &c, 1) == 1);

    // Child is in a new session, so we can't make it the foregroup process
    // group.
    TEST_PCHECK(ioctl(replica_.get(), TIOCSPGRP, &grandchild) &&
                errno == EPERM);

    TEST_PCHECK(WriteFd(sync_exit[1], &c, 1) == 1);

    int wstatus;
    TEST_PCHECK(waitpid(grandchild, &wstatus, 0) == grandchild);
    TEST_PCHECK(WIFEXITED(wstatus));
    TEST_PCHECK(!WEXITSTATUS(wstatus));
  });
  ASSERT_NO_ERRNO(ret);
}

// Verify that we don't hang when creating a new session from an orphaned
// process group (b/139968068). Calling setsid() creates an orphaned process
// group, as process groups that contain the session's leading process are
// orphans.
//
// We create 2 sessions in this test. The init process in gVisor is considered
// not to be an orphan (see sessions.go), so we have to create a session from
// which to create a session. The latter session is being created from an
// orphaned process group.
TEST_F(JobControlTest, OrphanRegression) {
  pid_t session_2_leader = fork();
  if (!session_2_leader) {
    TEST_PCHECK(setsid() >= 0);

    pid_t session_3_leader = fork();
    if (!session_3_leader) {
      TEST_PCHECK(setsid() >= 0);

      _exit(0);
    }

    int wstatus;
    TEST_PCHECK(waitpid(session_3_leader, &wstatus, 0) == session_3_leader);
    TEST_PCHECK(wstatus == 0);

    _exit(0);
  }

  int wstatus;
  ASSERT_THAT(waitpid(session_2_leader, &wstatus, 0),
              SyscallSucceedsWithValue(session_2_leader));
  ASSERT_EQ(wstatus, 0);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
