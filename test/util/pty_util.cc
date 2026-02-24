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

#include "test/util/pty_util.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <termios.h>

#include <cctype>
#include <cstring>
#include <ostream>
#include <string>

#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

namespace {

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

}  // namespace

bool operator==(struct kernel_termios const& a,
                struct kernel_termios const& b) {
  return memcmp(&a, &b, sizeof(a)) == 0;
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
  os << ", c_line = " << (int)a.c_line;
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

PosixErrorOr<FileDescriptor> OpenReplica(const FileDescriptor& master) {
  return OpenReplica(master, O_NONBLOCK | O_RDWR | O_NOCTTY);
}

PosixErrorOr<FileDescriptor> OpenReplica(const FileDescriptor& master,
                                         int flags) {
  PosixErrorOr<int> n = ReplicaID(master);
  if (!n.ok()) {
    return PosixErrorOr<FileDescriptor>(n.error());
  }
  return Open(absl::StrCat("/dev/pts/", n.ValueOrDie()), flags);
}

PosixErrorOr<int> ReplicaID(const FileDescriptor& master) {
  // Get pty index.
  int n;
  int ret = ioctl(master.get(), TIOCGPTN, &n);
  if (ret < 0) {
    return PosixError(errno, "ioctl(TIOCGPTN) failed");
  }

  // Unlock pts.
  int unlock = 0;
  ret = ioctl(master.get(), TIOCSPTLCK, &unlock);
  if (ret < 0) {
    return PosixError(errno, "ioctl(TIOCSPTLCK) failed");
  }

  return n;
}

}  // namespace testing
}  // namespace gvisor
