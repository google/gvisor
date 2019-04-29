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

// Utilities for syscall testing.
//
// Initialization
// ==============
//
// Prior to calling RUN_ALL_TESTS, all tests must use TestInit(&argc, &argv).
// See the TestInit function for exact side-effects and semantics.
//
// Configuration
// =============
//
// IsRunningOnGvisor returns true if the test is known to be running on gVisor.
// GvisorPlatform can be used to get more detail:
//
//   switch (GvisorPlatform()) {
//     case Platform::kNative:
//     case Platform::kGvisor:
//       EXPECT_THAT(mmap(...), SyscallSucceeds());
//       break;
//     case Platform::kPtrace:
//       EXPECT_THAT(mmap(...), SyscallFailsWithErrno(ENOSYS));
//       break;
//   }
//
// Matchers
// ========
//
// ElementOf(xs) matches if the matched value is equal to an element of the
// container xs. Example:
//
//   // PASS
//   EXPECT_THAT(1, ElementOf({0, 1, 2}));
//
//   // FAIL
//   // Value of: 3
//   // Expected: one of {0, 1, 2}
//   //   Actual: 3
//   EXPECT_THAT(3, ElementOf({0, 1, 2}));
//
// SyscallSucceeds() matches if the syscall is successful. A successful syscall
// is defined by either a return value not equal to -1, or a return value of -1
// with an errno of 0 (which is a possible successful return for e.g.
// PTRACE_PEEK). Example:
//
//   // PASS
//   EXPECT_THAT(open("/dev/null", O_RDONLY), SyscallSucceeds());
//
//   // FAIL
//   // Value of: open("/", O_RDWR)
//   // Expected: not -1 (success)
//   //   Actual: -1 (of type int), with errno 21 (Is a directory)
//   EXPECT_THAT(open("/", O_RDWR), SyscallSucceeds());
//
// SyscallSucceedsWithValue(m) matches if the syscall is successful, and the
// value also matches m. Example:
//
//   // PASS
//   EXPECT_THAT(read(4, buf, 8192), SyscallSucceedsWithValue(8192));
//
//   // FAIL
//   // Value of: read(-1, buf, 8192)
//   // Expected: is equal to 8192
//   //   Actual: -1 (of type long), with errno 9 (Bad file number)
//   EXPECT_THAT(read(-1, buf, 8192), SyscallSucceedsWithValue(8192));
//
//   // FAIL
//   // Value of: read(4, buf, 1)
//   // Expected: is > 4096
//   //   Actual: 1 (of type long)
//   EXPECT_THAT(read(4, buf, 1), SyscallSucceedsWithValue(Gt(4096)));
//
// SyscallFails() matches if the syscall is unsuccessful. An unsuccessful
// syscall is defined by a return value of -1 with a non-zero errno. Example:
//
//   // PASS
//   EXPECT_THAT(open("/", O_RDWR), SyscallFails());
//
//   // FAIL
//   // Value of: open("/dev/null", O_RDONLY)
//   // Expected: -1 (failure)
//   //   Actual: 0 (of type int)
//   EXPECT_THAT(open("/dev/null", O_RDONLY), SyscallFails());
//
// SyscallFailsWithErrno(m) matches if the syscall is unsuccessful, and errno
// matches m. Example:
//
//   // PASS
//   EXPECT_THAT(open("/", O_RDWR), SyscallFailsWithErrno(EISDIR));
//
//   // PASS
//   EXPECT_THAT(open("/etc/passwd", O_RDWR | O_DIRECTORY),
//               SyscallFailsWithErrno(AnyOf(EACCES, ENOTDIR)));
//
//   // FAIL
//   // Value of: open("/dev/null", O_RDONLY)
//   // Expected: -1 (failure) with errno 21 (Is a directory)
//   //   Actual: 0 (of type int)
//   EXPECT_THAT(open("/dev/null", O_RDONLY), SyscallFailsWithErrno(EISDIR));
//
//   // FAIL
//   // Value of: open("/", O_RDWR)
//   // Expected: -1 (failure) with errno 22 (Invalid argument)
//   //   Actual: -1 (of type int), failure, but with errno 21 (Is a directory)
//   EXPECT_THAT(open("/", O_RDWR), SyscallFailsWithErrno(EINVAL));
//
// Because the syscall matchers encode save/restore functionality, their meaning
// should not be inverted via Not. That is, AnyOf(SyscallSucceedsWithValue(1),
// SyscallSucceedsWithValue(2)) is permitted, but not
// Not(SyscallFailsWithErrno(EPERM)).
//
// Syscalls
// ========
//
// RetryEINTR wraps a function that returns -1 and sets errno on failure
// to be automatically retried when EINTR occurs. Example:
//
//   auto rv = RetryEINTR(waitpid)(pid, &status, 0);
//
// ReadFd/WriteFd/PreadFd/PwriteFd are interface-compatible wrappers around the
// read/write/pread/pwrite syscalls to handle both EINTR and partial
// reads/writes. Example:
//
//   EXPECT_THAT(ReadFd(fd, &buf, size), SyscallSucceedsWithValue(size));
//
// General Utilities
// =================
//
// ApplyVec(f, xs) returns a vector containing the result of applying function
// `f` to each value in `xs`.
//
// AllBitwiseCombinations takes a variadic number of ranges containing integers
// and returns a vector containing every integer that can be formed by ORing
// together exactly one integer from each list. List<T> is an alias for
// std::initializer_list<T> that makes AllBitwiseCombinations more ergonomic to
// use with list literals (initializer lists do not otherwise participate in
// template argument deduction). Example:
//
//     EXPECT_THAT(
//         AllBitwiseCombinations<int>(
//             List<int>{SOCK_DGRAM, SOCK_STREAM},
//             List<int>{0, SOCK_NONBLOCK}),
//         Contains({SOCK_DGRAM, SOCK_STREAM, SOCK_DGRAM | SOCK_NONBLOCK,
//                   SOCK_STREAM | SOCK_NONBLOCK}));
//
// VecCat takes a variadic number of containers and returns a vector containing
// the concatenated contents.
//
// VecAppend takes an initial container and a variadic number of containers and
// appends each to the initial container.
//
// RandomizeBuffer will use MTRandom to fill the given buffer with random bytes.
//
// GenerateIovecs will return the smallest number of iovec arrays for writing a
// given total number of bytes to a file, each iovec array size up to IOV_MAX,
// each iovec in each array pointing to the same buffer.

#ifndef GVISOR_TEST_UTIL_TEST_UTIL_H_
#define GVISOR_TEST_UTIL_TEST_UTIL_H_

#include <stddef.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <initializer_list>
#include <iterator>
#include <string>
#include <thread>  // NOLINT: using std::thread::hardware_concurrency().
#include <utility>
#include <vector>

#include <gflags/gflags.h>
#include "gmock/gmock.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"

namespace gvisor {
namespace testing {

// TestInit must be called prior to RUN_ALL_TESTS.
//
// This parses all arguments and adjusts argc and argv appropriately.
//
// TestInit may create background threads.
void TestInit(int* argc, char*** argv);

// SKIP_IF may be used to skip a test case.
//
// These cases are still emitted, but a SKIPPED line will appear.
#define SKIP_IF(expr)                \
  do {                               \
    if (expr) GTEST_SKIP() << #expr; \
  } while (0)

enum class Platform {
  kNative,
  kKVM,
  kPtrace,
};
bool IsRunningOnGvisor();
Platform GvisorPlatform();

void SetupGvisorDeathTest();

struct KernelVersion {
  int major;
  int minor;
  int micro;
};

bool operator==(const KernelVersion& first, const KernelVersion& second);

PosixErrorOr<KernelVersion> ParseKernelVersion(absl::string_view vers_string);
PosixErrorOr<KernelVersion> GetKernelVersion();

static const size_t kPageSize = sysconf(_SC_PAGESIZE);

enum class CPUVendor { kIntel, kAMD, kUnknownVendor };

CPUVendor GetCPUVendor();

inline int NumCPUs() { return std::thread::hardware_concurrency(); }

// Converts cpu_set_t to a std::string for easy examination.
std::string CPUSetToString(const cpu_set_t& set, size_t cpus = CPU_SETSIZE);

struct OpenFd {
  // fd is the open file descriptor number.
  int fd = -1;

  // link is the resolution of the symbolic link.
  std::string link;
};

// Make it easier to log OpenFds to error streams.
std::ostream& operator<<(std::ostream& out, std::vector<OpenFd> const& v);
std::ostream& operator<<(std::ostream& out, OpenFd const& ofd);

// Gets a detailed list of open fds for this process.
PosixErrorOr<std::vector<OpenFd>> GetOpenFDs();

// Returns the number of hard links to a path.
PosixErrorOr<uint64_t> Links(const std::string& path);

namespace internal {

template <typename Container>
class ElementOfMatcher {
 public:
  explicit ElementOfMatcher(Container container)
      : container_(::std::move(container)) {}

  template <typename T>
  bool MatchAndExplain(T const& rv,
                       ::testing::MatchResultListener* const listener) const {
    using std::count;
    return count(container_.begin(), container_.end(), rv) != 0;
  }

  void DescribeTo(::std::ostream* const os) const {
    *os << "one of {";
    char const* sep = "";
    for (auto const& elem : container_) {
      *os << sep << elem;
      sep = ", ";
    }
    *os << "}";
  }

  void DescribeNegationTo(::std::ostream* const os) const {
    *os << "none of {";
    char const* sep = "";
    for (auto const& elem : container_) {
      *os << sep << elem;
      sep = ", ";
    }
    *os << "}";
  }

 private:
  Container const container_;
};

template <typename E>
class SyscallSuccessMatcher {
 public:
  explicit SyscallSuccessMatcher(E expected)
      : expected_(::std::move(expected)) {}

  template <typename T>
  operator ::testing::Matcher<T>() const {
    // E is one of three things:
    // - T, or a type losslessly and implicitly convertible to T.
    // - A monomorphic Matcher<T>.
    // - A polymorphic matcher.
    // SafeMatcherCast handles any of the above correctly.
    //
    // Similarly, gMock will invoke this conversion operator to obtain a
    // monomorphic matcher (this is how polymorphic matchers are implemented).
    return ::testing::MakeMatcher(
        new Impl<T>(::testing::SafeMatcherCast<T>(expected_)));
  }

 private:
  template <typename T>
  class Impl : public ::testing::MatcherInterface<T> {
   public:
    explicit Impl(::testing::Matcher<T> matcher)
        : matcher_(::std::move(matcher)) {}

    bool MatchAndExplain(
        T const& rv,
        ::testing::MatchResultListener* const listener) const override {
      if (rv == static_cast<decltype(rv)>(-1) && errno != 0) {
        *listener << "with errno " << PosixError(errno);
        return false;
      }
      bool match = matcher_.MatchAndExplain(rv, listener);
      if (match) {
        MaybeSave();
      }
      return match;
    }

    void DescribeTo(::std::ostream* const os) const override {
      matcher_.DescribeTo(os);
    }

    void DescribeNegationTo(::std::ostream* const os) const override {
      matcher_.DescribeNegationTo(os);
    }

   private:
    ::testing::Matcher<T> matcher_;
  };

 private:
  E expected_;
};

// A polymorphic matcher equivalent to ::testing::internal::AnyMatcher, except
// not in namespace ::testing::internal, and describing SyscallSucceeds()'s
// match constraints (which are enforced by SyscallSuccessMatcher::Impl).
class AnySuccessValueMatcher {
 public:
  template <typename T>
  operator ::testing::Matcher<T>() const {
    return ::testing::MakeMatcher(new Impl<T>());
  }

 private:
  template <typename T>
  class Impl : public ::testing::MatcherInterface<T> {
   public:
    bool MatchAndExplain(
        T const& rv,
        ::testing::MatchResultListener* const listener) const override {
      return true;
    }

    void DescribeTo(::std::ostream* const os) const override {
      *os << "not -1 (success)";
    }

    void DescribeNegationTo(::std::ostream* const os) const override {
      *os << "-1 (failure)";
    }
  };
};

class SyscallFailureMatcher {
 public:
  explicit SyscallFailureMatcher(::testing::Matcher<int> errno_matcher)
      : errno_matcher_(std::move(errno_matcher)) {}

  template <typename T>
  bool MatchAndExplain(T const& rv,
                       ::testing::MatchResultListener* const listener) const {
    if (rv != static_cast<decltype(rv)>(-1)) {
      return false;
    }
    int actual_errno = errno;
    *listener << "with errno " << PosixError(actual_errno);
    bool match = errno_matcher_.MatchAndExplain(actual_errno, listener);
    if (match) {
      MaybeSave();
    }
    return match;
  }

  void DescribeTo(::std::ostream* const os) const {
    *os << "-1 (failure), with errno ";
    errno_matcher_.DescribeTo(os);
  }

  void DescribeNegationTo(::std::ostream* const os) const {
    *os << "not -1 (success), with errno ";
    errno_matcher_.DescribeNegationTo(os);
  }

 private:
  ::testing::Matcher<int> errno_matcher_;
};

class SpecificErrnoMatcher : public ::testing::MatcherInterface<int> {
 public:
  explicit SpecificErrnoMatcher(int const expected) : expected_(expected) {}

  bool MatchAndExplain(
      int const actual_errno,
      ::testing::MatchResultListener* const listener) const override {
    return actual_errno == expected_;
  }

  void DescribeTo(::std::ostream* const os) const override {
    *os << PosixError(expected_);
  }

  void DescribeNegationTo(::std::ostream* const os) const override {
    *os << "not " << PosixError(expected_);
  }

 private:
  int const expected_;
};

inline ::testing::Matcher<int> SpecificErrno(int const expected) {
  return ::testing::MakeMatcher(new SpecificErrnoMatcher(expected));
}

}  // namespace internal

template <typename Container>
inline ::testing::PolymorphicMatcher<internal::ElementOfMatcher<Container>>
ElementOf(Container container) {
  return ::testing::MakePolymorphicMatcher(
      internal::ElementOfMatcher<Container>(::std::move(container)));
}

template <typename T>
inline ::testing::PolymorphicMatcher<
    internal::ElementOfMatcher<::std::vector<T>>>
ElementOf(::std::initializer_list<T> elems) {
  return ::testing::MakePolymorphicMatcher(
      internal::ElementOfMatcher<::std::vector<T>>(::std::vector<T>(elems)));
}

template <typename E>
inline internal::SyscallSuccessMatcher<E> SyscallSucceedsWithValue(E expected) {
  return internal::SyscallSuccessMatcher<E>(::std::move(expected));
}

inline internal::SyscallSuccessMatcher<internal::AnySuccessValueMatcher>
SyscallSucceeds() {
  return SyscallSucceedsWithValue(
      ::gvisor::testing::internal::AnySuccessValueMatcher());
}

inline ::testing::PolymorphicMatcher<internal::SyscallFailureMatcher>
SyscallFailsWithErrno(::testing::Matcher<int> expected) {
  return ::testing::MakePolymorphicMatcher(
      internal::SyscallFailureMatcher(::std::move(expected)));
}

// Overload taking an int so that SyscallFailsWithErrno(<specific errno>) uses
// internal::SpecificErrno (which stringifies the errno) rather than
// ::testing::Eq (which doesn't).
inline ::testing::PolymorphicMatcher<internal::SyscallFailureMatcher>
SyscallFailsWithErrno(int const expected) {
  return SyscallFailsWithErrno(internal::SpecificErrno(expected));
}

inline ::testing::PolymorphicMatcher<internal::SyscallFailureMatcher>
SyscallFails() {
  return SyscallFailsWithErrno(::testing::Gt(0));
}

// As of GCC 7.2, -Wall => -Wc++17-compat => -Wnoexcept-type generates an
// irrelevant, non-actionable warning about ABI compatibility when
// RetryEINTRImpl is constructed with a noexcept function, such as glibc's
// syscall(). See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80985.
#if defined(__GNUC__) && !defined(__clang__) && \
    (__GNUC__ > 7 || (__GNUC__ == 7 && __GNUC_MINOR__ >= 2))
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnoexcept-type"
#endif

namespace internal {

template <typename F>
struct RetryEINTRImpl {
  F const f;

  explicit constexpr RetryEINTRImpl(F f) : f(std::move(f)) {}

  template <typename... Args>
  auto operator()(Args&&... args) const
      -> decltype(f(std::forward<Args>(args)...)) {
    while (true) {
      errno = 0;
      auto const ret = f(std::forward<Args>(args)...);
      if (ret != -1 || errno != EINTR) {
        return ret;
      }
    }
  }
};

}  // namespace internal

template <typename F>
constexpr internal::RetryEINTRImpl<F> RetryEINTR(F&& f) {
  return internal::RetryEINTRImpl<F>(std::forward<F>(f));
}

#if defined(__GNUC__) && !defined(__clang__) && \
    (__GNUC__ > 7 || (__GNUC__ == 7 && __GNUC_MINOR__ >= 2))
#pragma GCC diagnostic pop
#endif

namespace internal {

template <typename F>
ssize_t ApplyFileIoSyscall(F const& f, size_t const count) {
  size_t completed = 0;
  // `do ... while` because some callers actually want to make a syscall with a
  // count of 0.
  do {
    auto const cur = RetryEINTR(f)(completed);
    if (cur < 0) {
      return cur;
    } else if (cur == 0) {
      break;
    }
    completed += cur;
  } while (completed < count);
  return completed;
}

}  // namespace internal

inline ssize_t ReadFd(int fd, void* buf, size_t count) {
  return internal::ApplyFileIoSyscall(
      [&](size_t completed) {
        return read(fd, static_cast<char*>(buf) + completed, count - completed);
      },
      count);
}

inline ssize_t WriteFd(int fd, void const* buf, size_t count) {
  return internal::ApplyFileIoSyscall(
      [&](size_t completed) {
        return write(fd, static_cast<char const*>(buf) + completed,
                     count - completed);
      },
      count);
}

inline ssize_t PreadFd(int fd, void* buf, size_t count, off_t offset) {
  return internal::ApplyFileIoSyscall(
      [&](size_t completed) {
        return pread(fd, static_cast<char*>(buf) + completed, count - completed,
                     offset + completed);
      },
      count);
}

inline ssize_t PwriteFd(int fd, void const* buf, size_t count, off_t offset) {
  return internal::ApplyFileIoSyscall(
      [&](size_t completed) {
        return pwrite(fd, static_cast<char const*>(buf) + completed,
                      count - completed, offset + completed);
      },
      count);
}

template <typename T>
using List = std::initializer_list<T>;

namespace internal {

template <typename T>
void AppendAllBitwiseCombinations(std::vector<T>* combinations, T current) {
  combinations->push_back(current);
}

template <typename T, typename Arg, typename... Args>
void AppendAllBitwiseCombinations(std::vector<T>* combinations, T current,
                                  Arg&& next, Args&&... rest) {
  for (auto const option : next) {
    AppendAllBitwiseCombinations(combinations, current | option, rest...);
  }
}

inline size_t CombinedSize(size_t accum) { return accum; }

template <typename T, typename... Args>
size_t CombinedSize(size_t accum, T const& x, Args&&... xs) {
  return CombinedSize(accum + x.size(), std::forward<Args>(xs)...);
}

// Base case: no more containers, so do nothing.
template <typename T>
void DoMoveExtendContainer(T* c) {}

// Append each container next to c.
template <typename T, typename U, typename... Args>
void DoMoveExtendContainer(T* c, U&& next, Args&&... rest) {
  std::move(std::begin(next), std::end(next), std::back_inserter(*c));
  DoMoveExtendContainer(c, std::forward<Args>(rest)...);
}

}  // namespace internal

template <typename T = int>
std::vector<T> AllBitwiseCombinations() {
  return std::vector<T>();
}

template <typename T = int, typename... Args>
std::vector<T> AllBitwiseCombinations(Args&&... args) {
  std::vector<T> combinations;
  internal::AppendAllBitwiseCombinations(&combinations, 0, args...);
  return combinations;
}

template <typename T, typename U, typename F>
std::vector<T> ApplyVec(F const& f, std::vector<U> const& us) {
  std::vector<T> vec;
  vec.reserve(us.size());
  for (auto const& u : us) {
    vec.push_back(f(u));
  }
  return vec;
}

template <typename T, typename U>
std::vector<T> ApplyVecToVec(std::vector<std::function<T(U)>> const& fs,
                             std::vector<U> const& us) {
  std::vector<T> vec;
  vec.reserve(us.size() * fs.size());
  for (auto const& f : fs) {
    for (auto const& u : us) {
      vec.push_back(f(u));
    }
  }
  return vec;
}

// Moves all elements from the containers `args` to the end of `c`.
template <typename T, typename... Args>
void VecAppend(T* c, Args&&... args) {
  c->reserve(internal::CombinedSize(c->size(), args...));
  internal::DoMoveExtendContainer(c, std::forward<Args>(args)...);
}

// Returns a vector containing the concatenated contents of the containers
// `args`.
template <typename T, typename... Args>
std::vector<T> VecCat(Args&&... args) {
  std::vector<T> combined;
  VecAppend(&combined, std::forward<Args>(args)...);
  return combined;
}

#define RETURN_ERROR_IF_SYSCALL_FAIL(syscall) \
  do {                                        \
    if ((syscall) < 0 && errno != 0) {        \
      return PosixError(errno, #syscall);     \
    }                                         \
  } while (false)

// Fill the given buffer with random bytes.
void RandomizeBuffer(void* buffer, size_t len);

template <typename T>
inline PosixErrorOr<T> Atoi(absl::string_view str) {
  T ret;
  if (!absl::SimpleAtoi<T>(str, &ret)) {
    return PosixError(EINVAL, "String not a number.");
  }
  return ret;
}

inline PosixErrorOr<uint64_t> AtoiBase(absl::string_view str, int base) {
  if (base > 255 || base < 2) {
    return PosixError(EINVAL, "Invalid Base");
  }

  uint64_t ret = 0;
  if (!absl::numbers_internal::safe_strtou64_base(str, &ret, base)) {
    return PosixError(EINVAL, "String not a number.");
  }

  return ret;
}

inline PosixErrorOr<double> Atod(absl::string_view str) {
  double ret;
  if (!absl::SimpleAtod(str, &ret)) {
    return PosixError(EINVAL, "String not a double type.");
  }
  return ret;
}

inline PosixErrorOr<float> Atof(absl::string_view str) {
  float ret;
  if (!absl::SimpleAtof(str, &ret)) {
    return PosixError(EINVAL, "String not a float type.");
  }
  return ret;
}

// Return the smallest number of iovec arrays that can be used to write
// "total_bytes" number of bytes, each iovec writing one "buf".
std::vector<std::vector<struct iovec>> GenerateIovecs(uint64_t total_size,
                                                      void* buf, size_t buflen);

// Sleep for at least the specified duration. Avoids glibc.
void SleepSafe(absl::Duration duration);

// Returns bytes in 'n' megabytes. Used for readability.
uint64_t Megabytes(uint64_t n);

// Predicate for checking that a value is within some tolerance of another
// value. Returns true iff current is in the range [target * (1 - tolerance),
// target * (1 + tolerance)].
bool Equivalent(uint64_t current, uint64_t target, double tolerance);

// Matcher wrapping the Equivalent predicate.
MATCHER_P2(EquivalentWithin, target, tolerance,
           std::string(negation ? "Isn't" : "Is") +
               ::absl::StrFormat(" within %.2f%% of the target of %zd bytes",
                                 tolerance * 100, target)) {
  if (target == 0) {
    *result_listener << ::absl::StreamFormat("difference of infinity%%");
  } else {
    int64_t delta = static_cast<int64_t>(arg) - static_cast<int64_t>(target);
    double delta_percent =
        static_cast<double>(delta) / static_cast<double>(target) * 100;
    *result_listener << ::absl::StreamFormat("difference of %.2f%%",
                                             delta_percent);
  }
  return Equivalent(arg, target, tolerance);
}

void TestInit(int* argc, char*** argv);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_TEST_UTIL_H_
