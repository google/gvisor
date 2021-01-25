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
#include <libgen.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <sys/xattr.h>

#include <atomic>
#include <list>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/epoll_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

using ::absl::StreamFormat;
using ::absl::StrFormat;

constexpr int kBufSize = 1024;

// C++-friendly version of struct inotify_event.
struct Event {
  int32_t wd;
  uint32_t mask;
  uint32_t cookie;
  uint32_t len;
  std::string name;

  Event(uint32_t mask, int32_t wd, absl::string_view name, uint32_t cookie)
      : wd(wd),
        mask(mask),
        cookie(cookie),
        len(name.size()),
        name(std::string(name)) {}
  Event(uint32_t mask, int32_t wd, absl::string_view name)
      : Event(mask, wd, name, 0) {}
  Event(uint32_t mask, int32_t wd) : Event(mask, wd, "", 0) {}
  Event() : Event(0, 0, "", 0) {}
};

// Prints the symbolic name for a struct inotify_event's 'mask' field.
std::string FlagString(uint32_t flags) {
  std::vector<std::string> names;

#define EMIT(target)          \
  if (flags & target) {       \
    names.push_back(#target); \
    flags &= ~target;         \
  }

  EMIT(IN_ACCESS);
  EMIT(IN_ATTRIB);
  EMIT(IN_CLOSE_WRITE);
  EMIT(IN_CLOSE_NOWRITE);
  EMIT(IN_CREATE);
  EMIT(IN_DELETE);
  EMIT(IN_DELETE_SELF);
  EMIT(IN_MODIFY);
  EMIT(IN_MOVE_SELF);
  EMIT(IN_MOVED_FROM);
  EMIT(IN_MOVED_TO);
  EMIT(IN_OPEN);

  EMIT(IN_DONT_FOLLOW);
  EMIT(IN_EXCL_UNLINK);
  EMIT(IN_ONESHOT);
  EMIT(IN_ONLYDIR);

  EMIT(IN_IGNORED);
  EMIT(IN_ISDIR);
  EMIT(IN_Q_OVERFLOW);
  EMIT(IN_UNMOUNT);

#undef EMIT

  // If we have anything left over at the end, print it as a hex value.
  if (flags) {
    names.push_back(absl::StrCat("0x", absl::Hex(flags)));
  }

  return absl::StrJoin(names, "|");
}

std::string DumpEvent(const Event& event) {
  return StrFormat(
      "%s, wd=%d%s%s", FlagString(event.mask), event.wd,
      (event.len > 0) ? StrFormat(", name=%s", event.name) : "",
      (event.cookie > 0) ? StrFormat(", cookie=%ud", event.cookie) : "");
}

std::string DumpEvents(const std::vector<Event>& events, int indent_level) {
  std::stringstream ss;
  ss << StreamFormat("%d event%s:\n", events.size(),
                     (events.size() > 1) ? "s" : "");
  int i = 0;
  for (const Event& ev : events) {
    ss << StreamFormat("%sevents[%d]: %s\n", std::string(indent_level, '\t'),
                       i++, DumpEvent(ev));
  }
  return ss.str();
}

// A matcher which takes an expected list of events to match against another
// list of inotify events, in order. This is similar to the ElementsAre matcher,
// but displays more informative messages on mismatch.
class EventsAreMatcher
    : public ::testing::MatcherInterface<std::vector<Event>> {
 public:
  explicit EventsAreMatcher(std::vector<Event> references)
      : references_(std::move(references)) {}

  bool MatchAndExplain(
      std::vector<Event> events,
      ::testing::MatchResultListener* const listener) const override {
    if (references_.size() != events.size()) {
      *listener << StreamFormat("\n\tCount mismatch, got %s",
                                DumpEvents(events, 2));
      return false;
    }

    bool success = true;
    for (unsigned int i = 0; i < references_.size(); ++i) {
      const Event& reference = references_[i];
      const Event& target = events[i];

      if (target.mask != reference.mask || target.wd != reference.wd ||
          target.name != reference.name || target.cookie != reference.cookie) {
        *listener << StreamFormat("\n\tMismatch at index %d, want %s, got %s,",
                                  i, DumpEvent(reference), DumpEvent(target));
        success = false;
      }
    }

    if (!success) {
      *listener << StreamFormat("\n\tIn total of %s", DumpEvents(events, 2));
    }
    return success;
  }

  void DescribeTo(::std::ostream* const os) const override {
    *os << StreamFormat("%s", DumpEvents(references_, 1));
  }

  void DescribeNegationTo(::std::ostream* const os) const override {
    *os << StreamFormat("mismatch from %s", DumpEvents(references_, 1));
  }

 private:
  std::vector<Event> references_;
};

::testing::Matcher<std::vector<Event>> Are(std::vector<Event> events) {
  return MakeMatcher(new EventsAreMatcher(std::move(events)));
}

// Similar to the EventsAre matcher, but the order of events are ignored.
class UnorderedEventsAreMatcher
    : public ::testing::MatcherInterface<std::vector<Event>> {
 public:
  explicit UnorderedEventsAreMatcher(std::vector<Event> references)
      : references_(std::move(references)) {}

  bool MatchAndExplain(
      std::vector<Event> events,
      ::testing::MatchResultListener* const listener) const override {
    if (references_.size() != events.size()) {
      *listener << StreamFormat("\n\tCount mismatch, got %s",
                                DumpEvents(events, 2));
      return false;
    }

    std::vector<Event> unmatched(references_);

    for (const Event& candidate : events) {
      for (auto it = unmatched.begin(); it != unmatched.end();) {
        const Event& reference = *it;
        if (candidate.mask == reference.mask && candidate.wd == reference.wd &&
            candidate.name == reference.name &&
            candidate.cookie == reference.cookie) {
          it = unmatched.erase(it);
          break;
        } else {
          ++it;
        }
      }
    }

    // Anything left unmatched? If so, the matcher fails.
    if (!unmatched.empty()) {
      *listener << StreamFormat("\n\tFailed to match %s",
                                DumpEvents(unmatched, 2));
      *listener << StreamFormat("\n\tIn total of %s", DumpEvents(events, 2));
      return false;
    }

    return true;
  }

  void DescribeTo(::std::ostream* const os) const override {
    *os << StreamFormat("unordered %s", DumpEvents(references_, 1));
  }

  void DescribeNegationTo(::std::ostream* const os) const override {
    *os << StreamFormat("mismatch from unordered %s",
                        DumpEvents(references_, 1));
  }

 private:
  std::vector<Event> references_;
};

::testing::Matcher<std::vector<Event>> AreUnordered(std::vector<Event> events) {
  return MakeMatcher(new UnorderedEventsAreMatcher(std::move(events)));
}

// Reads events from an inotify fd until either EOF, or read returns EAGAIN.
PosixErrorOr<std::vector<Event>> DrainEvents(int fd) {
  std::vector<Event> events;
  while (true) {
    int events_size = 0;
    if (ioctl(fd, FIONREAD, &events_size) < 0) {
      return PosixError(errno, "ioctl(FIONREAD) failed on inotify fd");
    }
    // Deliberately use a buffer that is larger than necessary, expecting to
    // only read events_size bytes.
    std::vector<char> buf(events_size + kBufSize, 0);
    const ssize_t readlen = read(fd, buf.data(), buf.size());
    MaybeSave();
    // Read error?
    if (readlen < 0) {
      if (errno == EAGAIN) {
        // If EAGAIN, no more events at the moment. Return what we have so far.
        return events;
      }
      // Some other read error. Return an error. Right now if we encounter this
      // after already reading some events, they get lost. However, we don't
      // expect to see any error, and the calling test will fail immediately if
      // we signal an error anyways, so this is acceptable.
      return PosixError(errno, "read() failed on inotify fd");
    }
    if (readlen < static_cast<int>(sizeof(struct inotify_event))) {
      // Impossibly short read.
      return PosixError(
          EIO,
          "read() didn't return enough data represent even a single event");
    }
    if (readlen != events_size) {
      return PosixError(EINVAL, absl::StrCat("read ", readlen,
                                             " bytes, expected ", events_size));
    }
    if (readlen == 0) {
      // EOF.
      return events;
    }

    // Normal read.
    const char* cursor = buf.data();
    while (cursor < (buf.data() + readlen)) {
      struct inotify_event event = {};
      memcpy(&event, cursor, sizeof(struct inotify_event));

      Event ev;
      ev.wd = event.wd;
      ev.mask = event.mask;
      ev.cookie = event.cookie;
      ev.len = event.len;
      if (event.len > 0) {
        TEST_CHECK(static_cast<int>(sizeof(struct inotify_event) + event.len) <=
                   readlen);
        ev.name = std::string(cursor +
                              offsetof(struct inotify_event, name));  // NOLINT
        // Name field should always be smaller than event.len, otherwise we have
        // a buffer overflow. The two sizes aren't equal because the string
        // constructor will stop at the first null byte, while event.name may be
        // padded up to event.len using multiple null bytes.
        TEST_CHECK(ev.name.size() <= event.len);
      }

      events.push_back(ev);
      cursor += sizeof(struct inotify_event) + event.len;
    }
  }
}

PosixErrorOr<FileDescriptor> InotifyInit1(int flags) {
  int fd = inotify_init1(flags);
  if (fd < 0) {
    return PosixError(errno, "inotify_init1() failed");
  }
  return FileDescriptor(fd);
}

PosixErrorOr<int> InotifyAddWatch(int fd, const std::string& path,
                                  uint32_t mask) {
  int wd = inotify_add_watch(fd, path.c_str(), mask);
  if (wd < 0) {
    return PosixError(errno, "inotify_add_watch() failed");
  }
  return wd;
}

TEST(Inotify, IllegalSeek) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(0));
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
}

TEST(Inotify, IllegalPread) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(0));
  int val;
  EXPECT_THAT(pread(fd.get(), &val, sizeof(val), 0),
              SyscallFailsWithErrno(ESPIPE));
}

TEST(Inotify, IllegalPwrite) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(0));
  EXPECT_THAT(pwrite(fd.get(), "x", 1, 0), SyscallFailsWithErrno(ESPIPE));
}

TEST(Inotify, IllegalWrite) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(0));
  int val = 0;
  EXPECT_THAT(write(fd.get(), &val, sizeof(val)), SyscallFailsWithErrno(EBADF));
}

TEST(Inotify, InitFlags) {
  EXPECT_THAT(inotify_init1(IN_NONBLOCK | IN_CLOEXEC), SyscallSucceeds());
  EXPECT_THAT(inotify_init1(12345), SyscallFailsWithErrno(EINVAL));
}

TEST(Inotify, NonBlockingReadReturnsEagain) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  std::vector<char> buf(kBufSize, 0);

  // The read below should return fail with EAGAIN because there is no data to
  // read and we've specified IN_NONBLOCK. We're guaranteed that there is no
  // data to read because we haven't registered any watches yet.
  EXPECT_THAT(read(fd.get(), buf.data(), buf.size()),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(Inotify, AddWatchOnInvalidFdFails) {
  // Garbage fd.
  EXPECT_THAT(inotify_add_watch(-1, "/tmp", IN_ALL_EVENTS),
              SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(inotify_add_watch(1337, "/tmp", IN_ALL_EVENTS),
              SyscallFailsWithErrno(EBADF));

  // Non-inotify fds.
  EXPECT_THAT(inotify_add_watch(0, "/tmp", IN_ALL_EVENTS),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(inotify_add_watch(1, "/tmp", IN_ALL_EVENTS),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(inotify_add_watch(2, "/tmp", IN_ALL_EVENTS),
              SyscallFailsWithErrno(EINVAL));
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/tmp", O_RDONLY));
  EXPECT_THAT(inotify_add_watch(fd.get(), "/tmp", IN_ALL_EVENTS),
              SyscallFailsWithErrno(EINVAL));
}

TEST(Inotify, RemovingWatchGeneratesEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  EXPECT_THAT(inotify_rm_watch(fd.get(), wd), SyscallSucceeds());

  // Read events, ensure the first event is IN_IGNORED.
  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  EXPECT_THAT(events, Are({Event(IN_IGNORED, wd)}));
}

TEST(Inotify, CanDeleteFileAfterRemovingWatch) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  EXPECT_THAT(inotify_rm_watch(fd.get(), wd), SyscallSucceeds());
  file1.reset();
}

TEST(Inotify, RemoveWatchAfterDeletingFileFails) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  file1.reset();
  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  EXPECT_THAT(events, Are({Event(IN_ATTRIB, wd), Event(IN_DELETE_SELF, wd),
                           Event(IN_IGNORED, wd)}));

  EXPECT_THAT(inotify_rm_watch(fd.get(), wd), SyscallFailsWithErrno(EINVAL));
}

TEST(Inotify, DuplicateWatchRemovalFails) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  EXPECT_THAT(inotify_rm_watch(fd.get(), wd), SyscallSucceeds());
  EXPECT_THAT(inotify_rm_watch(fd.get(), wd), SyscallFailsWithErrno(EINVAL));
}

TEST(Inotify, ConcurrentFileDeletionAndWatchRemoval) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const std::string filename = NewTempAbsPathInDir(root.path());

  auto file_create_delete = [filename]() {
    const DisableSave ds;  // Too expensive.
    for (int i = 0; i < 100; ++i) {
      FileDescriptor file_fd =
          ASSERT_NO_ERRNO_AND_VALUE(Open(filename, O_CREAT, S_IRUSR | S_IWUSR));
      // Close before unlinking (although S/R is disabled). Some filesystems
      // cannot restore an open fd on an unlinked file.
      file_fd.reset();
      EXPECT_THAT(unlink(filename.c_str()), SyscallSucceeds());
    }
  };

  const int shared_fd = fd.get();  // We need to pass it to the thread.
  auto add_remove_watch = [shared_fd, filename]() {
    for (int i = 0; i < 100; ++i) {
      int wd = inotify_add_watch(shared_fd, filename.c_str(), IN_ALL_EVENTS);
      MaybeSave();
      if (wd != -1) {
        // Watch added successfully, try removal.
        if (inotify_rm_watch(shared_fd, wd)) {
          // If removal fails, the only acceptable reason is if the wd
          // is invalid, which will be the case if we try to remove
          // the watch after the file has been deleted.
          EXPECT_EQ(errno, EINVAL);
        }
      } else {
        // Add watch failed, this should only fail if the target file doesn't
        // exist.
        EXPECT_EQ(errno, ENOENT);
      }
    }
  };

  ScopedThread t1(file_create_delete);
  ScopedThread t2(add_remove_watch);
}

TEST(Inotify, DeletingChildGeneratesEvents) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int root_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  const int file1_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  const std::string file1_path = file1.reset();

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(
      events,
      AreUnordered({Event(IN_ATTRIB, file1_wd), Event(IN_DELETE_SELF, file1_wd),
                    Event(IN_IGNORED, file1_wd),
                    Event(IN_DELETE, root_wd, Basename(file1_path))}));
}

// Creating a file in "parent/child" should generate events for child, but not
// parent.
TEST(Inotify, CreatingFileGeneratesEvents) {
  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath child =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), parent.path(), IN_ALL_EVENTS));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), child.path(), IN_ALL_EVENTS));

  // Create a new file in the directory.
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(child.path()));
  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));

  // The library function we use to create the new file opens it for writing to
  // create it and sets permissions on it, so we expect the three extra events.
  ASSERT_THAT(events, Are({Event(IN_CREATE, wd, Basename(file1.path())),
                           Event(IN_OPEN, wd, Basename(file1.path())),
                           Event(IN_CLOSE_WRITE, wd, Basename(file1.path())),
                           Event(IN_ATTRIB, wd, Basename(file1.path()))}));
}

TEST(Inotify, ReadingFileGeneratesAccessEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const TempPath file1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      root.path(), "some content", TempPath::kDefaultFileMode));

  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDONLY));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  char buf;
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_ACCESS, wd, Basename(file1.path()))}));
}

TEST(Inotify, WritingFileGeneratesModifyEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_WRONLY));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  const std::string data = "some content";
  EXPECT_THAT(write(file1_fd.get(), data.c_str(), data.length()),
              SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_MODIFY, wd, Basename(file1.path()))}));
}

TEST(Inotify, SizeZeroReadWriteGeneratesNothing) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDWR));
  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  // Read from the empty file.
  int val;
  ASSERT_THAT(read(file1_fd.get(), &val, sizeof(val)),
              SyscallSucceedsWithValue(0));

  // Write zero bytes.
  ASSERT_THAT(write(file1_fd.get(), "", 0), SyscallSucceedsWithValue(0));

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({}));
}

TEST(Inotify, FailedFileCreationGeneratesNoEvents) {
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir_path = dir.path();
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  ASSERT_NO_ERRNO_AND_VALUE(InotifyAddWatch(fd.get(), dir_path, IN_ALL_EVENTS));

  const char* p = dir_path.c_str();
  ASSERT_THAT(mkdir(p, 0777), SyscallFails());
  ASSERT_THAT(mknod(p, S_IFIFO, 0777), SyscallFails());
  ASSERT_THAT(symlink(p, p), SyscallFails());
  ASSERT_THAT(link(p, p), SyscallFails());
  std::vector<Event> events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({}));
}

TEST(Inotify, WatchSetAfterOpenReportsCloseFdEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  FileDescriptor file1_fd_writable =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_WRONLY));
  FileDescriptor file1_fd_not_writable =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDONLY));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  file1_fd_writable.reset();  // Close file1_fd_writable.
  std::vector<Event> events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_CLOSE_WRITE, wd, Basename(file1.path()))}));

  file1_fd_not_writable.reset();  // Close file1_fd_not_writable.
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events,
              Are({Event(IN_CLOSE_NOWRITE, wd, Basename(file1.path()))}));
}

TEST(Inotify, ChildrenDeletionInWatchedDirGeneratesEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  TempPath dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));

  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  const std::string file1_path = file1.reset();
  const std::string dir1_path = dir1.release();
  EXPECT_THAT(rmdir(dir1_path.c_str()), SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));

  ASSERT_THAT(events,
              Are({Event(IN_DELETE, wd, Basename(file1_path)),
                   Event(IN_DELETE | IN_ISDIR, wd, Basename(dir1_path))}));
}

TEST(Inotify, RmdirOnWatchedTargetGeneratesEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  EXPECT_THAT(rmdir(root.path().c_str()), SyscallSucceeds());
  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_DELETE_SELF, wd), Event(IN_IGNORED, wd)}));
}

TEST(Inotify, MoveGeneratesEvents) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  const TempPath dir1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath dir2 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));

  const int root_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  const int dir1_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), dir1.path(), IN_ALL_EVENTS));
  const int dir2_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), dir2.path(), IN_ALL_EVENTS));
  // Test move from root -> root.
  std::string newpath = NewTempAbsPathInDir(root.path());
  std::string oldpath = file1.release();
  EXPECT_THAT(rename(oldpath.c_str(), newpath.c_str()), SyscallSucceeds());
  file1.reset(newpath);
  std::vector<Event> events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(
      events,
      Are({Event(IN_MOVED_FROM, root_wd, Basename(oldpath), events[0].cookie),
           Event(IN_MOVED_TO, root_wd, Basename(newpath), events[1].cookie)}));
  EXPECT_NE(events[0].cookie, 0);
  EXPECT_EQ(events[0].cookie, events[1].cookie);
  uint32_t last_cookie = events[0].cookie;

  // Test move from root -> root/dir1.
  newpath = NewTempAbsPathInDir(dir1.path());
  oldpath = file1.release();
  EXPECT_THAT(rename(oldpath.c_str(), newpath.c_str()), SyscallSucceeds());
  file1.reset(newpath);
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(
      events,
      Are({Event(IN_MOVED_FROM, root_wd, Basename(oldpath), events[0].cookie),
           Event(IN_MOVED_TO, dir1_wd, Basename(newpath), events[1].cookie)}));
  // Cookies should be distinct between distinct rename events.
  EXPECT_NE(events[0].cookie, last_cookie);
  EXPECT_EQ(events[0].cookie, events[1].cookie);
  last_cookie = events[0].cookie;

  // Test move from root/dir1 -> root/dir2.
  newpath = NewTempAbsPathInDir(dir2.path());
  oldpath = file1.release();
  EXPECT_THAT(rename(oldpath.c_str(), newpath.c_str()), SyscallSucceeds());
  file1.reset(newpath);
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(
      events,
      Are({Event(IN_MOVED_FROM, dir1_wd, Basename(oldpath), events[0].cookie),
           Event(IN_MOVED_TO, dir2_wd, Basename(newpath), events[1].cookie)}));
  EXPECT_NE(events[0].cookie, last_cookie);
  EXPECT_EQ(events[0].cookie, events[1].cookie);
  last_cookie = events[0].cookie;
}

TEST(Inotify, MoveWatchedTargetGeneratesEvents) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  const int root_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  const int file1_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  const std::string newpath = NewTempAbsPathInDir(root.path());
  const std::string oldpath = file1.release();
  EXPECT_THAT(rename(oldpath.c_str(), newpath.c_str()), SyscallSucceeds());
  file1.reset(newpath);
  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(
      events,
      Are({Event(IN_MOVED_FROM, root_wd, Basename(oldpath), events[0].cookie),
           Event(IN_MOVED_TO, root_wd, Basename(newpath), events[1].cookie),
           // Self move events do not have a cookie.
           Event(IN_MOVE_SELF, file1_wd)}));
  EXPECT_NE(events[0].cookie, 0);
  EXPECT_EQ(events[0].cookie, events[1].cookie);
}

TEST(Inotify, CoalesceEvents) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const TempPath file1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      root.path(), "some content", TempPath::kDefaultFileMode));

  FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDONLY));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  // Read the file a few times. This will would generate multiple IN_ACCESS
  // events but they should get coalesced to a single event.
  char buf;
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());

  // Use the close event verify that we haven't simply left the additional
  // IN_ACCESS events unread.
  file1_fd.reset();  // Close file1_fd.

  const std::string file1_name = std::string(Basename(file1.path()));
  std::vector<Event> events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_ACCESS, wd, file1_name),
                           Event(IN_CLOSE_NOWRITE, wd, file1_name)}));

  // Now let's try interleaving other events into a stream of repeated events.
  file1_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDWR));

  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());
  EXPECT_THAT(write(file1_fd.get(), "x", 1), SyscallSucceeds());
  EXPECT_THAT(write(file1_fd.get(), "x", 1), SyscallSucceeds());
  EXPECT_THAT(write(file1_fd.get(), "x", 1), SyscallSucceeds());
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());

  file1_fd.reset();  // Close the file.

  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(
      events,
      Are({Event(IN_OPEN, wd, file1_name), Event(IN_ACCESS, wd, file1_name),
           Event(IN_MODIFY, wd, file1_name), Event(IN_ACCESS, wd, file1_name),
           Event(IN_CLOSE_WRITE, wd, file1_name)}));

  // Ensure events aren't coalesced if they are from different files.
  const TempPath file2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      root.path(), "some content", TempPath::kDefaultFileMode));
  // Discard events resulting from creation of file2.
  ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));

  file1_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDONLY));
  FileDescriptor file2_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file2.path(), O_RDONLY));

  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());
  EXPECT_THAT(read(file2_fd.get(), &buf, 1), SyscallSucceeds());
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());

  // Close both files.
  file1_fd.reset();
  file2_fd.reset();

  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  const std::string file2_name = std::string(Basename(file2.path()));
  ASSERT_THAT(
      events,
      Are({Event(IN_OPEN, wd, file1_name), Event(IN_OPEN, wd, file2_name),
           Event(IN_ACCESS, wd, file1_name), Event(IN_ACCESS, wd, file2_name),
           Event(IN_ACCESS, wd, file1_name),
           Event(IN_CLOSE_NOWRITE, wd, file1_name),
           Event(IN_CLOSE_NOWRITE, wd, file2_name)}));
}

TEST(Inotify, ClosingInotifyFdWithoutRemovingWatchesWorks) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDONLY));

  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));
  // Note: The check on close will happen in FileDescriptor::~FileDescriptor().
}

TEST(Inotify, NestedWatches) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const TempPath file1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      root.path(), "some content", TempPath::kDefaultFileMode));
  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDONLY));

  const int root_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  const int file1_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  // Read from file1. This should generate an event for both watches.
  char buf;
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_ACCESS, root_wd, Basename(file1.path())),
                           Event(IN_ACCESS, file1_wd)}));
}

TEST(Inotify, ConcurrentThreadsGeneratingEvents) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  std::vector<TempPath> files;
  files.reserve(10);
  for (int i = 0; i < 10; i++) {
    files.emplace_back(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
        root.path(), "some content", TempPath::kDefaultFileMode)));
  }

  auto test_thread = [&files]() {
    uint32_t seed = time(nullptr);
    for (int i = 0; i < 20; i++) {
      const TempPath& file = files[rand_r(&seed) % files.size()];
      const FileDescriptor file_fd =
          ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_WRONLY));
      TEST_PCHECK(write(file_fd.get(), "x", 1) == 1);
    }
  };

  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  std::list<ScopedThread> threads;
  for (int i = 0; i < 3; i++) {
    threads.emplace_back(test_thread);
  }
  for (auto& t : threads) {
    t.Join();
  }

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  // 3 threads doing 20 iterations, 3 events per iteration (open, write,
  // close). However, some events may be coalesced, and we can't reliably
  // predict how they'll be coalesced since the test threads aren't
  // synchronized. We can only check that we aren't getting unexpected events.
  for (const Event& ev : events) {
    EXPECT_NE(ev.mask & (IN_OPEN | IN_MODIFY | IN_CLOSE_WRITE), 0);
  }
}

TEST(Inotify, ReadWithTooSmallBufferFails) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  // Open the file to queue an event. This event will not have a filename, so
  // reading from the inotify fd should return sizeof(struct inotify_event)
  // bytes of data.
  FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDONLY));
  std::vector<char> buf(kBufSize, 0);
  ssize_t readlen;

  // Try a buffer too small to hold any potential event. This is rejected
  // outright without the event being dequeued.
  EXPECT_THAT(read(fd.get(), buf.data(), sizeof(struct inotify_event) - 1),
              SyscallFailsWithErrno(EINVAL));
  // Try a buffer just large enough. This should succeeed.
  EXPECT_THAT(
      readlen = read(fd.get(), buf.data(), sizeof(struct inotify_event)),
      SyscallSucceeds());
  EXPECT_EQ(readlen, sizeof(struct inotify_event));
  // Event queue is now empty, the next read should return EAGAIN.
  EXPECT_THAT(read(fd.get(), buf.data(), sizeof(struct inotify_event)),
              SyscallFailsWithErrno(EAGAIN));

  // Now put a watch on the directory, so that generated events contain a name.
  EXPECT_THAT(inotify_rm_watch(fd.get(), wd), SyscallSucceeds());

  // Drain the event generated from the watch removal.
  ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));

  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  file1_fd.reset();  // Close file to generate an event.

  // Try a buffer too small to hold any event and one too small to hold an event
  // with a name. These should both fail without consuming the event.
  EXPECT_THAT(read(fd.get(), buf.data(), sizeof(struct inotify_event) - 1),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(read(fd.get(), buf.data(), sizeof(struct inotify_event)),
              SyscallFailsWithErrno(EINVAL));
  // Now try with a large enough buffer. This should return the one event.
  EXPECT_THAT(readlen = read(fd.get(), buf.data(), buf.size()),
              SyscallSucceeds());
  EXPECT_GE(readlen,
            sizeof(struct inotify_event) + Basename(file1.path()).size());
  // With the single event read, the queue should once again be empty.
  EXPECT_THAT(read(fd.get(), buf.data(), sizeof(struct inotify_event)),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(Inotify, BlockingReadOnInotifyFd) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(0));
  const TempPath file1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      root.path(), "some content", TempPath::kDefaultFileMode));

  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDONLY));

  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  // Spawn a thread performing a blocking read for new events on the inotify fd.
  std::vector<char> buf(kBufSize, 0);
  const int shared_fd = fd.get();  // The thread needs it.
  ScopedThread t([shared_fd, &buf]() {
    ssize_t readlen;
    EXPECT_THAT(readlen = read(shared_fd, buf.data(), buf.size()),
                SyscallSucceeds());
  });

  // Perform a read on the watched file, which should generate an IN_ACCESS
  // event, unblocking the event_reader thread.
  char c;
  EXPECT_THAT(read(file1_fd.get(), &c, 1), SyscallSucceeds());

  // Wait for the thread to read the event and exit.
  t.Join();

  // Make sure the event we got back is sane.
  uint32_t event_mask;
  memcpy(&event_mask, buf.data() + offsetof(struct inotify_event, mask),
         sizeof(event_mask));
  EXPECT_EQ(event_mask, IN_ACCESS);
}

TEST(Inotify, WatchOnRelativePath) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const TempPath file1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      root.path(), "some content", TempPath::kDefaultFileMode));

  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDONLY));

  // Change working directory to root.
  const FileDescriptor cwd = ASSERT_NO_ERRNO_AND_VALUE(Open(".", O_PATH));
  EXPECT_THAT(chdir(root.path().c_str()), SyscallSucceeds());

  // Add a watch on file1 with a relative path.
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(InotifyAddWatch(
      fd.get(), std::string(Basename(file1.path())), IN_ALL_EVENTS));

  // Perform a read on file1, this should generate an IN_ACCESS event.
  char c;
  EXPECT_THAT(read(file1_fd.get(), &c, 1), SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  EXPECT_THAT(events, Are({Event(IN_ACCESS, wd)}));

  // Explicitly reset the working directory so that we don't continue to
  // reference "root". Once the test ends, "root" will get unlinked. If we
  // continue to hold a reference, random save/restore tests can fail if a save
  // is triggered after "root" is unlinked; we can't save deleted fs objects
  // with active references.
  EXPECT_THAT(fchdir(cwd.get()), SyscallSucceeds());
}

TEST(Inotify, ZeroLengthReadWriteDoesNotGenerateEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const char kContent[] = "some content";
  TempPath file1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      root.path(), kContent, TempPath::kDefaultFileMode));
  const int kContentSize = sizeof(kContent) - 1;

  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDWR));

  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  std::vector<char> buf(kContentSize, 0);
  // Read all available data.
  ssize_t readlen;
  EXPECT_THAT(readlen = read(file1_fd.get(), buf.data(), kContentSize),
              SyscallSucceeds());
  EXPECT_EQ(readlen, kContentSize);
  // Drain all events and make sure we got the IN_ACCESS for the read.
  std::vector<Event> events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  EXPECT_THAT(events, Are({Event(IN_ACCESS, wd, Basename(file1.path()))}));

  // Now try read again. This should be a 0-length read, since we're at EOF.
  char c;
  EXPECT_THAT(readlen = read(file1_fd.get(), &c, 1), SyscallSucceeds());
  EXPECT_EQ(readlen, 0);
  // We should have no new events.
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  EXPECT_TRUE(events.empty());

  // Try issuing a zero-length read.
  EXPECT_THAT(readlen = read(file1_fd.get(), &c, 0), SyscallSucceeds());
  EXPECT_EQ(readlen, 0);
  // We should have no new events.
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  EXPECT_TRUE(events.empty());

  // Try issuing a zero-length write.
  ssize_t writelen;
  EXPECT_THAT(writelen = write(file1_fd.get(), &c, 0), SyscallSucceeds());
  EXPECT_EQ(writelen, 0);
  // We should have no new events.
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  EXPECT_TRUE(events.empty());
}

TEST(Inotify, ChmodGeneratesAttribEvent_NoRandomSave) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  FileDescriptor root_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(root.path(), O_RDONLY));
  FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDWR));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int root_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  const int file1_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  auto verify_chmod_events = [&]() {
    std::vector<Event> events =
        ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
    ASSERT_THAT(events, Are({Event(IN_ATTRIB, root_wd, Basename(file1.path())),
                             Event(IN_ATTRIB, file1_wd)}));
  };

  // Don't do cooperative S/R tests for any of the {f}chmod* syscalls below, the
  // test will always fail because nodes cannot be saved when they have stricter
  // permissions than the original host node.
  const DisableSave ds;

  // Chmod.
  ASSERT_THAT(chmod(file1.path().c_str(), S_IWGRP), SyscallSucceeds());
  verify_chmod_events();

  // Fchmod.
  ASSERT_THAT(fchmod(file1_fd.get(), S_IRGRP | S_IWGRP), SyscallSucceeds());
  verify_chmod_events();

  // Fchmodat.
  const std::string file1_basename = std::string(Basename(file1.path()));
  ASSERT_THAT(fchmodat(root_fd.get(), file1_basename.c_str(), S_IWGRP, 0),
              SyscallSucceeds());
  verify_chmod_events();

  // Make sure the chmod'ed file descriptors are destroyed before DisableSave
  // is destructed.
  root_fd.reset();
  file1_fd.reset();
}

TEST(Inotify, TruncateGeneratesModifyEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDWR));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int root_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  const int file1_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  auto verify_truncate_events = [&]() {
    std::vector<Event> events =
        ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
    ASSERT_THAT(events, Are({Event(IN_MODIFY, root_wd, Basename(file1.path())),
                             Event(IN_MODIFY, file1_wd)}));
  };

  // Truncate.
  EXPECT_THAT(truncate(file1.path().c_str(), 4096), SyscallSucceeds());
  verify_truncate_events();

  // Ftruncate.
  EXPECT_THAT(ftruncate(file1_fd.get(), 8192), SyscallSucceeds());
  verify_truncate_events();

  // No events if truncate fails.
  EXPECT_THAT(ftruncate(file1_fd.get(), -1), SyscallFailsWithErrno(EINVAL));
  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({}));
}

TEST(Inotify, GetdentsGeneratesAccessEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  // This internally calls getdents(2). We also expect to see an open/close
  // event for the dirfd.
  ASSERT_NO_ERRNO_AND_VALUE(ListDir(root.path(), false));
  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));

  // Linux only seems to generate access events on getdents() on some
  // calls. Allow the test to pass even if it isn't generated. gVisor will
  // always generate the IN_ACCESS event so the test will at least ensure gVisor
  // behaves reasonably.
  int i = 0;
  EXPECT_EQ(events[i].mask, IN_OPEN | IN_ISDIR);
  ++i;
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(events[i].mask, IN_ACCESS | IN_ISDIR);
    ++i;
  } else {
    if (events[i].mask == (IN_ACCESS | IN_ISDIR)) {
      // Skip over the IN_ACCESS event on Linux, it only shows up some of the
      // time so we can't assert its existence.
      ++i;
    }
  }
  EXPECT_EQ(events[i].mask, IN_CLOSE_NOWRITE | IN_ISDIR);
}

TEST(Inotify, MknodGeneratesCreateEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  const TempPath file1(root.path() + "/file1");
  ASSERT_THAT(mknod(file1.path().c_str(), S_IFREG, 0), SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_CREATE, wd, Basename(file1.path()))}));
}

TEST(Inotify, SymlinkGeneratesCreateEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const TempPath link1(NewTempAbsPathInDir(root.path()));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int root_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  ASSERT_THAT(symlink(file1.path().c_str(), link1.path().c_str()),
              SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));

  ASSERT_THAT(events, Are({Event(IN_CREATE, root_wd, Basename(link1.path()))}));
}

TEST(Inotify, LinkGeneratesAttribAndCreateEvents) {
  // Inotify does not work properly with hard links in gofer and overlay fs.
  SKIP_IF(IsRunningOnGvisor() &&
          !ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(GetAbsoluteTestTmpdir())));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const TempPath link1(root.path() + "/link1");
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int root_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  const int file1_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  ASSERT_THAT(link(file1.path().c_str(), link1.path().c_str()),
              SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_ATTRIB, file1_wd),
                           Event(IN_CREATE, root_wd, Basename(link1.path()))}));
}

TEST(Inotify, UtimesGeneratesAttribEvent) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDWR));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));

  const struct timeval times[2] = {{1, 0}, {2, 0}};
  EXPECT_THAT(futimes(file1_fd.get(), times), SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_ATTRIB, wd, Basename(file1.path()))}));
}

TEST(Inotify, HardlinksReuseSameWatch) {
  // Inotify does not work properly with hard links in gofer and overlay fs.
  SKIP_IF(IsRunningOnGvisor() &&
          !ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(GetAbsoluteTestTmpdir())));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  TempPath file2(root.path() + "/file2");
  ASSERT_THAT(link(file.path().c_str(), file2.path().c_str()),
              SyscallSucceeds());

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int root_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  const int file_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file.path(), IN_ALL_EVENTS));
  const int file2_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file2.path(), IN_ALL_EVENTS));

  // The watch descriptors for watches on different links to the same file
  // should be identical.
  EXPECT_NE(root_wd, file_wd);
  EXPECT_EQ(file_wd, file2_wd);

  FileDescriptor file_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_WRONLY));

  std::vector<Event> events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events,
              AreUnordered({Event(IN_OPEN, root_wd, Basename(file.path())),
                            Event(IN_OPEN, file_wd)}));

  // For the next step, we want to ensure all fds to the file are closed. Do
  // that now and drain the resulting events.
  file_fd.reset();
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(
      events,
      AreUnordered({Event(IN_CLOSE_WRITE, root_wd, Basename(file.path())),
                    Event(IN_CLOSE_WRITE, file_wd)}));

  // Try removing the link and let's see what events show up. Note that after
  // this, we still have a link to the file so the watch shouldn't be
  // automatically removed.
  const std::string file2_path = file2.reset();

  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events,
              AreUnordered({Event(IN_ATTRIB, file2_wd),
                            Event(IN_DELETE, root_wd, Basename(file2_path))}));

  // Now remove the other link. Since this is the last link to the file, the
  // watch should be automatically removed.
  const std::string file_path = file.reset();

  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(
      events,
      AreUnordered({Event(IN_ATTRIB, file_wd), Event(IN_DELETE_SELF, file_wd),
                    Event(IN_IGNORED, file_wd),
                    Event(IN_DELETE, root_wd, Basename(file_path))}));
}

// Calling mkdir within "parent/child" should generate an event for child, but
// not parent.
TEST(Inotify, MkdirGeneratesCreateEventWithDirFlag) {
  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath child =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), parent.path(), IN_ALL_EVENTS));
  const int child_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), child.path(), IN_ALL_EVENTS));

  const TempPath dir1(NewTempAbsPathInDir(child.path()));
  ASSERT_THAT(mkdir(dir1.path().c_str(), 0777), SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(
      events,
      Are({Event(IN_CREATE | IN_ISDIR, child_wd, Basename(dir1.path()))}));
}

TEST(Inotify, MultipleInotifyInstancesAndWatchesAllGetEvents) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));

  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_WRONLY));
  constexpr int kNumFds = 30;
  std::vector<FileDescriptor> inotify_fds;

  for (int i = 0; i < kNumFds; ++i) {
    const DisableSave ds;  // Too expensive.
    inotify_fds.emplace_back(
        ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK)));
    const FileDescriptor& fd = inotify_fds[inotify_fds.size() - 1];  // Back.
    ASSERT_NO_ERRNO_AND_VALUE(
        InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
    ASSERT_NO_ERRNO_AND_VALUE(
        InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));
  }

  const std::string data = "some content";
  EXPECT_THAT(write(file1_fd.get(), data.c_str(), data.length()),
              SyscallSucceeds());

  for (const FileDescriptor& fd : inotify_fds) {
    const DisableSave ds;  // Too expensive.
    const std::vector<Event> events =
        ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
    if (events.size() >= 2) {
      EXPECT_EQ(events[0].mask, IN_MODIFY);
      EXPECT_EQ(events[0].wd, 1);
      EXPECT_EQ(events[0].name, Basename(file1.path()));
      EXPECT_EQ(events[1].mask, IN_MODIFY);
      EXPECT_EQ(events[1].wd, 2);
      EXPECT_EQ(events[1].name, "");
    }
  }
}

TEST(Inotify, EventsGoUpAtMostOneLevel) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath dir1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), root.path(), IN_ALL_EVENTS));
  const int dir1_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), dir1.path(), IN_ALL_EVENTS));

  const std::string file1_path = file1.reset();

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_DELETE, dir1_wd, Basename(file1_path))}));
}

TEST(Inotify, DuplicateWatchReturnsSameWatchDescriptor) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int wd1 = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));
  const int wd2 = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  EXPECT_EQ(wd1, wd2);

  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_WRONLY));
  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  // The watch shouldn't be duplicated, we only expect one event.
  ASSERT_THAT(events, Are({Event(IN_OPEN, wd1)}));
}

TEST(Inotify, UnmatchedEventsAreDiscarded) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ACCESS));

  FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_WRONLY));

  std::vector<Event> events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  // We only asked for access events, the open event should be discarded.
  ASSERT_THAT(events, Are({}));

  // IN_IGNORED events are always generated, regardless of the mask.
  file1_fd.reset();
  file1.reset();
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_IGNORED, wd)}));
}

TEST(Inotify, AddWatchWithInvalidEventMaskFails) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  EXPECT_THAT(inotify_add_watch(fd.get(), root.path().c_str(), 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(Inotify, AddWatchOnInvalidPathFails) {
  const TempPath nonexistent(NewTempAbsPath());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  // Non-existent path.
  EXPECT_THAT(
      inotify_add_watch(fd.get(), nonexistent.path().c_str(), IN_CREATE),
      SyscallFailsWithErrno(ENOENT));

  // Garbage path pointer.
  EXPECT_THAT(inotify_add_watch(fd.get(), nullptr, IN_CREATE),
              SyscallFailsWithErrno(EFAULT));
}

TEST(Inotify, InOnlyDirFlagRespected) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  EXPECT_THAT(
      inotify_add_watch(fd.get(), root.path().c_str(), IN_ACCESS | IN_ONLYDIR),
      SyscallSucceeds());

  EXPECT_THAT(
      inotify_add_watch(fd.get(), file1.path().c_str(), IN_ACCESS | IN_ONLYDIR),
      SyscallFailsWithErrno(ENOTDIR));
}

TEST(Inotify, MaskAddMergesWithExistingEventMask) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file1 =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_WRONLY));

  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_OPEN | IN_CLOSE_WRITE));

  const std::string data = "some content";
  EXPECT_THAT(write(file1_fd.get(), data.c_str(), data.length()),
              SyscallSucceeds());

  // We shouldn't get any events, since IN_MODIFY wasn't in the event mask.
  std::vector<Event> events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({}));

  // Add IN_MODIFY to event mask.
  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_MODIFY | IN_MASK_ADD));

  EXPECT_THAT(write(file1_fd.get(), data.c_str(), data.length()),
              SyscallSucceeds());

  // This time we should get the modify event.
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_MODIFY, wd)}));

  // Now close the fd. If the modify event was added to the event mask rather
  // than replacing the event mask we won't get the close event.
  file1_fd.reset();
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events, Are({Event(IN_CLOSE_WRITE, wd)}));
}

// Test that control events bits are not considered when checking event mask.
TEST(Inotify, ControlEvents) {
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), dir.path(), IN_ACCESS));

  // Check that events in the mask are dispatched and that control bits are
  // part of the event mask.
  std::vector<std::string> files =
      ASSERT_NO_ERRNO_AND_VALUE(ListDir(dir.path(), false));
  ASSERT_EQ(files.size(), 2);

  const std::vector<Event> events1 =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events1, Are({Event(IN_ACCESS | IN_ISDIR, wd)}));

  // Check that events not in the mask are discarded.
  const FileDescriptor dir_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_RDONLY | O_DIRECTORY));

  const std::vector<Event> events2 =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  ASSERT_THAT(events2, Are({}));
}

// Regression test to ensure epoll and directory access doesn't deadlock.
TEST(Inotify, EpollNoDeadlock) {
  const DisableSave ds;  // Too many syscalls.

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  // Create lots of directories and watch all of them.
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::vector<TempPath> children;
  for (size_t i = 0; i < 1000; ++i) {
    auto child = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
    ASSERT_NO_ERRNO_AND_VALUE(
        InotifyAddWatch(fd.get(), child.path(), IN_ACCESS));
    children.emplace_back(std::move(child));
  }

  // Run epoll_wait constantly in a separate thread.
  std::atomic<bool> done(false);
  ScopedThread th([&fd, &done] {
    for (auto start = absl::Now(); absl::Now() - start < absl::Seconds(5);) {
      FileDescriptor epoll_fd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
      ASSERT_NO_ERRNO(RegisterEpollFD(epoll_fd.get(), fd.get(),
                                      EPOLLIN | EPOLLOUT | EPOLLET, 0));
      struct epoll_event result[1];
      EXPECT_THAT(RetryEINTR(epoll_wait)(epoll_fd.get(), result, 1, -1),
                  SyscallSucceedsWithValue(1));

      sched_yield();
    }
    done = true;
  });

  // While epoll thread is running, constantly access all directories to
  // generate inotify events.
  while (!done) {
    std::vector<std::string> files =
        ASSERT_NO_ERRNO_AND_VALUE(ListDir(root.path(), false));
    ASSERT_EQ(files.size(), 1002);
    for (const auto& child : files) {
      if (child == "." || child == "..") {
        continue;
      }
      ASSERT_NO_ERRNO_AND_VALUE(ListDir(JoinPath(root.path(), child), false));
    }
    sched_yield();
  }
}

TEST(Inotify, Fallocate) {
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(inotify_fd.get(), file.path(), IN_ALL_EVENTS));

  // Do an arbitrary modification with fallocate.
  ASSERT_THAT(RetryEINTR(fallocate)(fd.get(), 0, 0, 123), SyscallSucceeds());
  std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({Event(IN_MODIFY, wd)}));
}

TEST(Inotify, Utimensat) {
  SKIP_IF(IsRunningWithVFS1());

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(inotify_fd.get(), file.path(), IN_ALL_EVENTS));

  // Just update the access time.
  struct timespec times[2] = {};
  times[0].tv_nsec = UTIME_NOW;
  times[1].tv_nsec = UTIME_OMIT;
  ASSERT_THAT(RetryEINTR(utimensat)(AT_FDCWD, file.path().c_str(), times, 0),
              SyscallSucceeds());
  std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({Event(IN_ACCESS, wd)}));

  // Just the modify time.
  times[0].tv_nsec = UTIME_OMIT;
  times[1].tv_nsec = UTIME_NOW;
  ASSERT_THAT(utimensat(AT_FDCWD, file.path().c_str(), times, 0),
              SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({Event(IN_MODIFY, wd)}));

  // Both together.
  times[0].tv_nsec = UTIME_NOW;
  times[1].tv_nsec = UTIME_NOW;
  ASSERT_THAT(utimensat(AT_FDCWD, file.path().c_str(), times, 0),
              SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({Event(IN_ATTRIB, wd)}));
}

TEST(Inotify, Sendfile) {
  SKIP_IF(IsRunningWithVFS1());

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(root.path(), "x", 0644));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor in =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));
  const FileDescriptor out =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

  // Create separate inotify instances for the in and out fds. If both watches
  // were on the same instance, we would have discrepancies between Linux and
  // gVisor (order of events, duplicate events), which is not that important
  // since inotify is asynchronous anyway.
  const FileDescriptor in_inotify =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const FileDescriptor out_inotify =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int in_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(in_inotify.get(), in_file.path(), IN_ALL_EVENTS));
  const int out_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(out_inotify.get(), out_file.path(), IN_ALL_EVENTS));

  ASSERT_THAT(sendfile(out.get(), in.get(), /*offset=*/nullptr, 1),
              SyscallSucceeds());

  // Expect a single access event and a single modify event.
  std::vector<Event> in_events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(in_inotify.get()));
  std::vector<Event> out_events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(out_inotify.get()));
  EXPECT_THAT(in_events, Are({Event(IN_ACCESS, in_wd)}));
  EXPECT_THAT(out_events, Are({Event(IN_MODIFY, out_wd)}));
}

// On Linux, inotify behavior is not very consistent with splice(2). We try our
// best to emulate Linux for very basic calls to splice.
TEST(Inotify, SpliceOnWatchTarget) {
  int pipes[2];
  ASSERT_THAT(pipe2(pipes, O_NONBLOCK), SyscallSucceeds());

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      dir.path(), "some content", TempPath::kDefaultFileMode));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));
  const int dir_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(inotify_fd.get(), dir.path(), IN_ALL_EVENTS));
  const int file_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(inotify_fd.get(), file.path(), IN_ALL_EVENTS));

  EXPECT_THAT(splice(fd.get(), nullptr, pipes[1], nullptr, 1, /*flags=*/0),
              SyscallSucceedsWithValue(1));

  // Surprisingly, events are not generated in Linux if we read from a file.
  std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  ASSERT_THAT(events, Are({}));

  EXPECT_THAT(splice(pipes[0], nullptr, fd.get(), nullptr, 1, /*flags=*/0),
              SyscallSucceedsWithValue(1));

  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  ASSERT_THAT(events, Are({
                          Event(IN_MODIFY, dir_wd, Basename(file.path())),
                          Event(IN_MODIFY, file_wd),
                      }));
}

TEST(Inotify, SpliceOnInotifyFD) {
  int pipes[2];
  ASSERT_THAT(pipe2(pipes, O_NONBLOCK), SyscallSucceeds());

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const TempPath file1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      root.path(), "some content", TempPath::kDefaultFileMode));

  const FileDescriptor file1_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file1.path(), O_RDONLY));
  const int watcher = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), file1.path(), IN_ALL_EVENTS));

  char buf;
  EXPECT_THAT(read(file1_fd.get(), &buf, 1), SyscallSucceeds());

  EXPECT_THAT(splice(fd.get(), nullptr, pipes[1], nullptr,
                     sizeof(struct inotify_event) + 1, SPLICE_F_NONBLOCK),
              SyscallSucceedsWithValue(sizeof(struct inotify_event)));

  const FileDescriptor read_fd(pipes[0]);
  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(read_fd.get()));
  ASSERT_THAT(events, Are({Event(IN_ACCESS, watcher)}));
}

// Watches on a parent should not be triggered by actions on a hard link to one
// of its children that has a different parent.
TEST(Inotify, LinkOnOtherParent) {
  // Inotify does not work properly with hard links in gofer and overlay fs.
  SKIP_IF(IsRunningOnGvisor() &&
          !ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(GetAbsoluteTestTmpdir())));

  const TempPath dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir1.path()));
  std::string link_path = NewTempAbsPathInDir(dir2.path());

  ASSERT_THAT(link(file.path().c_str(), link_path.c_str()), SyscallSucceeds());

  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(inotify_fd.get(), dir1.path(), IN_ALL_EVENTS));

  // Perform various actions on the link outside of dir1, which should trigger
  // no inotify events.
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(link_path.c_str(), O_RDWR));
  int val = 0;
  ASSERT_THAT(write(fd.get(), &val, sizeof(val)), SyscallSucceeds());
  ASSERT_THAT(read(fd.get(), &val, sizeof(val)), SyscallSucceeds());
  ASSERT_THAT(ftruncate(fd.get(), 12345), SyscallSucceeds());

  // Close before unlinking; some filesystems cannot restore an open fd on an
  // unlinked file.
  fd.reset();
  ASSERT_THAT(unlink(link_path.c_str()), SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({}));
}

TEST(Inotify, Xattr) {
  // TODO(gvisor.dev/issue/1636): Support extended attributes in runsc gofer.
  SKIP_IF(IsRunningOnGvisor());

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string path = file.path();
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR));
  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(inotify_fd.get(), path, IN_ALL_EVENTS));

  const char* cpath = path.c_str();
  const char* name = "user.test";
  int val = 123;
  ASSERT_THAT(setxattr(cpath, name, &val, sizeof(val), /*flags=*/0),
              SyscallSucceeds());
  std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({Event(IN_ATTRIB, wd)}));

  ASSERT_THAT(getxattr(cpath, name, &val, sizeof(val)), SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({}));

  char list[100];
  ASSERT_THAT(listxattr(cpath, list, sizeof(list)), SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({}));

  ASSERT_THAT(removexattr(cpath, name), SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({Event(IN_ATTRIB, wd)}));

  ASSERT_THAT(fsetxattr(fd.get(), name, &val, sizeof(val), /*flags=*/0),
              SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({Event(IN_ATTRIB, wd)}));

  ASSERT_THAT(fgetxattr(fd.get(), name, &val, sizeof(val)), SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({}));

  ASSERT_THAT(flistxattr(fd.get(), list, sizeof(list)), SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({}));

  ASSERT_THAT(fremovexattr(fd.get(), name), SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({Event(IN_ATTRIB, wd)}));
}

TEST(Inotify, Exec) {
  // TODO(gvisor.dev/issues/5348)
  SKIP_IF(IsRunningOnGvisor());

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(fd.get(), "/bin/true", IN_ALL_EVENTS));

  // Perform exec.
  pid_t child = -1;
  int execve_errno = -1;
  auto kill = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec("/bin/true", {}, {}, nullptr, &child, &execve_errno));
  ASSERT_EQ(0, execve_errno);

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0), SyscallSucceeds());
  EXPECT_EQ(0, status);

  // Process cleanup no longer needed.
  kill.Release();

  std::vector<Event> events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(fd.get()));
  EXPECT_THAT(events, Are({Event(IN_OPEN, wd), Event(IN_ACCESS, wd),
                           Event(IN_CLOSE_NOWRITE, wd)}));
}

// Watches without IN_EXCL_UNLINK, should continue to emit events for file
// descriptors after their corresponding files have been unlinked.
//
// We need to disable S/R because there are filesystems where we cannot re-open
// fds to an unlinked file across S/R, e.g. gofer-backed filesytems.
TEST(Inotify, IncludeUnlinkedFile_NoRandomSave) {
  const DisableSave ds;

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "123", TempPath::kDefaultFileMode));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int dir_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(inotify_fd.get(), dir.path(), IN_ALL_EVENTS));
  const int file_wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(inotify_fd.get(), file.path(), IN_ALL_EVENTS));

  ASSERT_THAT(unlink(file.path().c_str()), SyscallSucceeds());
  int val = 0;
  ASSERT_THAT(read(fd.get(), &val, sizeof(val)), SyscallSucceeds());
  ASSERT_THAT(write(fd.get(), &val, sizeof(val)), SyscallSucceeds());
  std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, AnyOf(Are({
                                Event(IN_ATTRIB, file_wd),
                                Event(IN_DELETE, dir_wd, Basename(file.path())),
                                Event(IN_ACCESS, dir_wd, Basename(file.path())),
                                Event(IN_ACCESS, file_wd),
                                Event(IN_MODIFY, dir_wd, Basename(file.path())),
                                Event(IN_MODIFY, file_wd),
                            }),
                            Are({
                                Event(IN_DELETE, dir_wd, Basename(file.path())),
                                Event(IN_ATTRIB, file_wd),
                                Event(IN_ACCESS, dir_wd, Basename(file.path())),
                                Event(IN_ACCESS, file_wd),
                                Event(IN_MODIFY, dir_wd, Basename(file.path())),
                                Event(IN_MODIFY, file_wd),
                            })));

  fd.reset();
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({
                          Event(IN_CLOSE_WRITE, dir_wd, Basename(file.path())),
                          Event(IN_CLOSE_WRITE, file_wd),
                          Event(IN_DELETE_SELF, file_wd),
                          Event(IN_IGNORED, file_wd),
                      }));
}

// Watches created with IN_EXCL_UNLINK will stop emitting events on fds for
// children that have already been unlinked.
//
// We need to disable S/R because there are filesystems where we cannot re-open
// fds to an unlinked file across S/R, e.g. gofer-backed filesytems.
TEST(Inotify, ExcludeUnlink_NoRandomSave) {
  const DisableSave ds;
  // TODO(gvisor.dev/issue/1624): This test fails on VFS1.
  SKIP_IF(IsRunningWithVFS1());

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int dir_wd = ASSERT_NO_ERRNO_AND_VALUE(InotifyAddWatch(
      inotify_fd.get(), dir.path(), IN_ALL_EVENTS | IN_EXCL_UNLINK));
  const int file_wd = ASSERT_NO_ERRNO_AND_VALUE(InotifyAddWatch(
      inotify_fd.get(), file.path(), IN_ALL_EVENTS | IN_EXCL_UNLINK));

  // Unlink the child, which should cause further operations on the open file
  // descriptor to be ignored.
  ASSERT_THAT(unlink(file.path().c_str()), SyscallSucceeds());
  int val = 0;
  ASSERT_THAT(write(fd.get(), &val, sizeof(val)), SyscallSucceeds());
  ASSERT_THAT(read(fd.get(), &val, sizeof(val)), SyscallSucceeds());
  std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, AreUnordered({
                          Event(IN_ATTRIB, file_wd),
                          Event(IN_DELETE, dir_wd, Basename(file.path())),
                      }));

  fd.reset();
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  ASSERT_THAT(events, Are({
                          Event(IN_DELETE_SELF, file_wd),
                          Event(IN_IGNORED, file_wd),
                      }));
}

// We need to disable S/R because there are filesystems where we cannot re-open
// fds to an unlinked file across S/R, e.g. gofer-backed filesytems.
TEST(Inotify, ExcludeUnlinkDirectory_NoRandomSave) {
  // TODO(gvisor.dev/issue/1624): This test fails on VFS1. Remove once VFS1 is
  // deleted.
  SKIP_IF(IsRunningWithVFS1());

  const DisableSave ds;

  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  std::string dirPath = dir.path();
  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dirPath.c_str(), O_RDONLY | O_DIRECTORY));
  const int parent_wd = ASSERT_NO_ERRNO_AND_VALUE(InotifyAddWatch(
      inotify_fd.get(), parent.path(), IN_ALL_EVENTS | IN_EXCL_UNLINK));
  const int self_wd = ASSERT_NO_ERRNO_AND_VALUE(InotifyAddWatch(
      inotify_fd.get(), dir.path(), IN_ALL_EVENTS | IN_EXCL_UNLINK));

  // Unlink the dir, and then close the open fd.
  ASSERT_THAT(rmdir(dirPath.c_str()), SyscallSucceeds());
  dir.reset();

  std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  // No close event should appear.
  ASSERT_THAT(events,
              Are({Event(IN_DELETE | IN_ISDIR, parent_wd, Basename(dirPath))}));

  fd.reset();
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  ASSERT_THAT(events, Are({
                          Event(IN_DELETE_SELF, self_wd),
                          Event(IN_IGNORED, self_wd),
                      }));
}

// If "dir/child" and "dir/child2" are links to the same file, and "dir/child"
// is unlinked, a watch on "dir" with IN_EXCL_UNLINK will exclude future events
// for fds on "dir/child" but not "dir/child2".
//
// We need to disable S/R because there are filesystems where we cannot re-open
// fds to an unlinked file across S/R, e.g. gofer-backed filesytems.
TEST(Inotify, ExcludeUnlinkMultipleChildren_NoRandomSave) {
  // Inotify does not work properly with hard links in gofer and overlay fs.
  SKIP_IF(IsRunningOnGvisor() &&
          !ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(GetAbsoluteTestTmpdir())));
  // TODO(gvisor.dev/issue/1624): This test fails on VFS1.
  SKIP_IF(IsRunningWithVFS1());

  const DisableSave ds;

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  std::string path1 = file.path();
  std::string path2 = NewTempAbsPathInDir(dir.path());
  ASSERT_THAT(link(path1.c_str(), path2.c_str()), SyscallSucceeds());

  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path1.c_str(), O_RDWR));
  const FileDescriptor fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path2.c_str(), O_RDWR));

  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int wd = ASSERT_NO_ERRNO_AND_VALUE(InotifyAddWatch(
      inotify_fd.get(), dir.path(), IN_ALL_EVENTS | IN_EXCL_UNLINK));

  // After unlinking path1, only events on the fd for path2 should be generated.
  ASSERT_THAT(unlink(path1.c_str()), SyscallSucceeds());
  ASSERT_THAT(write(fd1.get(), "x", 1), SyscallSucceeds());
  ASSERT_THAT(write(fd2.get(), "x", 1), SyscallSucceeds());

  const std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({
                          Event(IN_DELETE, wd, Basename(path1)),
                          Event(IN_MODIFY, wd, Basename(path2)),
                      }));
}

// On native Linux, actions of data type FSNOTIFY_EVENT_INODE are not affected
// by IN_EXCL_UNLINK (see
// fs/notify/inotify/inotify_fsnotify.c:inotify_handle_event). Inode-level
// events include changes to metadata and extended attributes.
//
// We need to disable S/R because there are filesystems where we cannot re-open
// fds to an unlinked file across S/R, e.g. gofer-backed filesytems.
TEST(Inotify, ExcludeUnlinkInodeEvents_NoRandomSave) {
  // TODO(gvisor.dev/issue/1624): Fails on VFS1.
  SKIP_IF(IsRunningWithVFS1());

  // NOTE(gvisor.dev/issue/3654): In the gofer filesystem, we do not allow
  // setting attributes through an fd if the file at the open path has been
  // deleted.
  SKIP_IF(IsRunningOnGvisor() &&
          !ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(GetAbsoluteTestTmpdir())));

  const DisableSave ds;

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path().c_str(), O_RDWR));

  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  const int dir_wd = ASSERT_NO_ERRNO_AND_VALUE(InotifyAddWatch(
      inotify_fd.get(), dir.path(), IN_ALL_EVENTS | IN_EXCL_UNLINK));
  const int file_wd = ASSERT_NO_ERRNO_AND_VALUE(InotifyAddWatch(
      inotify_fd.get(), file.path(), IN_ALL_EVENTS | IN_EXCL_UNLINK));

  // Even after unlinking, inode-level operations will trigger events regardless
  // of IN_EXCL_UNLINK.
  ASSERT_THAT(unlink(file.path().c_str()), SyscallSucceeds());

  // Perform various actions on fd.
  ASSERT_THAT(ftruncate(fd.get(), 12345), SyscallSucceeds());
  std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, AnyOf(Are({
                                Event(IN_ATTRIB, file_wd),
                                Event(IN_DELETE, dir_wd, Basename(file.path())),
                                Event(IN_MODIFY, dir_wd, Basename(file.path())),
                                Event(IN_MODIFY, file_wd),
                            }),
                            Are({
                                Event(IN_DELETE, dir_wd, Basename(file.path())),
                                Event(IN_ATTRIB, file_wd),
                                Event(IN_MODIFY, dir_wd, Basename(file.path())),
                                Event(IN_MODIFY, file_wd),
                            })));

  const struct timeval times[2] = {{1, 0}, {2, 0}};
  ASSERT_THAT(futimes(fd.get(), times), SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({
                          Event(IN_ATTRIB, dir_wd, Basename(file.path())),
                          Event(IN_ATTRIB, file_wd),
                      }));

  // S/R is disabled on this entire test due to behavior with unlink; it must
  // also be disabled after this point because of fchmod.
  ASSERT_THAT(fchmod(fd.get(), 0777), SyscallSucceeds());
  events = ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({
                          Event(IN_ATTRIB, dir_wd, Basename(file.path())),
                          Event(IN_ATTRIB, file_wd),
                      }));
}

TEST(Inotify, OneShot) {
  // TODO(gvisor.dev/issue/1624): IN_ONESHOT not supported in VFS1.
  SKIP_IF(IsRunningWithVFS1());

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));

  const int wd = ASSERT_NO_ERRNO_AND_VALUE(
      InotifyAddWatch(inotify_fd.get(), file.path(), IN_MODIFY | IN_ONESHOT));

  // Open an fd, write to it, and then close it.
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_WRONLY));
  ASSERT_THAT(write(fd.get(), "x", 1), SyscallSucceedsWithValue(1));
  fd.reset();

  // We should get a single event followed by IN_IGNORED indicating removal
  // of the one-shot watch. Prior activity (i.e. open) that is not in the mask
  // should not trigger removal, and activity after removal (i.e. close) should
  // not generate events.
  std::vector<Event> events =
      ASSERT_NO_ERRNO_AND_VALUE(DrainEvents(inotify_fd.get()));
  EXPECT_THAT(events, Are({
                          Event(IN_MODIFY, wd),
                          Event(IN_IGNORED, wd),
                      }));

  // The watch should already have been removed.
  EXPECT_THAT(inotify_rm_watch(inotify_fd.get(), wd),
              SyscallFailsWithErrno(EINVAL));
}

// This test helps verify that the lock order of filesystem and inotify locks
// is respected when inotify instances and watch targets are concurrently being
// destroyed.
TEST(InotifyTest, InotifyAndTargetDestructionDoNotDeadlock_NoRandomSave) {
  const DisableSave ds;  // Too many syscalls.

  // A file descriptor protected by a mutex. This ensures that while a
  // descriptor is in use, it cannot be closed and reused for a different file
  // description.
  struct atomic_fd {
    int fd;
    absl::Mutex mu;
  };

  // Set up initial inotify instances.
  constexpr int num_fds = 3;
  std::vector<atomic_fd> fds(num_fds);
  for (int i = 0; i < num_fds; i++) {
    int fd;
    ASSERT_THAT(fd = inotify_init1(IN_NONBLOCK), SyscallSucceeds());
    fds[i].fd = fd;
  }

  // Set up initial watch targets.
  std::vector<std::string> paths;
  for (int i = 0; i < 3; i++) {
    paths.push_back(NewTempAbsPath());
    ASSERT_THAT(mknod(paths[i].c_str(), S_IFREG | 0600, 0), SyscallSucceeds());
  }

  constexpr absl::Duration runtime = absl::Seconds(4);

  // Constantly replace each inotify instance with a new one.
  auto replace_fds = [&] {
    for (auto start = absl::Now(); absl::Now() - start < runtime;) {
      for (auto& afd : fds) {
        int new_fd;
        ASSERT_THAT(new_fd = inotify_init1(IN_NONBLOCK), SyscallSucceeds());
        absl::MutexLock l(&afd.mu);
        ASSERT_THAT(close(afd.fd), SyscallSucceeds());
        afd.fd = new_fd;
        for (auto& p : paths) {
          // inotify_add_watch may fail if the file at p was deleted.
          ASSERT_THAT(inotify_add_watch(afd.fd, p.c_str(), IN_ALL_EVENTS),
                      AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(ENOENT)));
        }
      }
      sched_yield();
    }
  };

  std::list<ScopedThread> ts;
  for (int i = 0; i < 3; i++) {
    ts.emplace_back(replace_fds);
  }

  // Constantly replace each watch target with a new one.
  for (auto start = absl::Now(); absl::Now() - start < runtime;) {
    for (auto& p : paths) {
      ASSERT_THAT(unlink(p.c_str()), SyscallSucceeds());
      ASSERT_THAT(mknod(p.c_str(), S_IFREG | 0600, 0), SyscallSucceeds());
    }
    sched_yield();
  }
}

// This test helps verify that the lock order of filesystem and inotify locks
// is respected when adding/removing watches occurs concurrently with the
// removal of their targets.
TEST(InotifyTest, AddRemoveUnlinkDoNotDeadlock_NoRandomSave) {
  const DisableSave ds;  // Too many syscalls.

  // Set up inotify instances.
  constexpr int num_fds = 3;
  std::vector<int> fds(num_fds);
  for (int i = 0; i < num_fds; i++) {
    ASSERT_THAT(fds[i] = inotify_init1(IN_NONBLOCK), SyscallSucceeds());
  }

  // Set up initial watch targets.
  std::vector<std::string> paths;
  for (int i = 0; i < 3; i++) {
    paths.push_back(NewTempAbsPath());
    ASSERT_THAT(mknod(paths[i].c_str(), S_IFREG | 0600, 0), SyscallSucceeds());
  }

  constexpr absl::Duration runtime = absl::Seconds(1);

  // Constantly add/remove watches for each inotify instance/watch target pair.
  auto add_remove_watches = [&] {
    for (auto start = absl::Now(); absl::Now() - start < runtime;) {
      for (int fd : fds) {
        for (auto& p : paths) {
          // Do not assert on inotify_add_watch and inotify_rm_watch. They may
          // fail if the file at p was deleted. inotify_add_watch may also fail
          // if another thread beat us to adding a watch.
          const int wd = inotify_add_watch(fd, p.c_str(), IN_ALL_EVENTS);
          if (wd > 0) {
            inotify_rm_watch(fd, wd);
          }
        }
      }
      sched_yield();
    }
  };

  std::list<ScopedThread> ts;
  for (int i = 0; i < 15; i++) {
    ts.emplace_back(add_remove_watches);
  }

  // Constantly replace each watch target with a new one.
  for (auto start = absl::Now(); absl::Now() - start < runtime;) {
    for (auto& p : paths) {
      ASSERT_THAT(unlink(p.c_str()), SyscallSucceeds());
      ASSERT_THAT(mknod(p.c_str(), S_IFREG | 0600, 0), SyscallSucceeds());
    }
    sched_yield();
  }
}

// This test helps verify that the lock order of filesystem and inotify locks
// is respected when many inotify events and filesystem operations occur
// simultaneously.
TEST(InotifyTest, NotifyNoDeadlock_NoRandomSave) {
  const DisableSave ds;  // Too many syscalls.

  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir = parent.path();

  // mu protects file, which will change on rename.
  absl::Mutex mu;
  std::string file = NewTempAbsPathInDir(dir);
  ASSERT_THAT(mknod(file.c_str(), 0644 | S_IFREG, 0), SyscallSucceeds());

  const absl::Duration runtime = absl::Milliseconds(300);

  // Add/remove watches on dir and file.
  ScopedThread add_remove_watches([&] {
    const FileDescriptor ifd =
        ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
    int dir_wd = ASSERT_NO_ERRNO_AND_VALUE(
        InotifyAddWatch(ifd.get(), dir, IN_ALL_EVENTS));
    int file_wd;
    {
      absl::ReaderMutexLock l(&mu);
      file_wd = ASSERT_NO_ERRNO_AND_VALUE(
          InotifyAddWatch(ifd.get(), file, IN_ALL_EVENTS));
    }
    for (auto start = absl::Now(); absl::Now() - start < runtime;) {
      ASSERT_THAT(inotify_rm_watch(ifd.get(), file_wd), SyscallSucceeds());
      ASSERT_THAT(inotify_rm_watch(ifd.get(), dir_wd), SyscallSucceeds());
      dir_wd = ASSERT_NO_ERRNO_AND_VALUE(
          InotifyAddWatch(ifd.get(), dir, IN_ALL_EVENTS));
      {
        absl::ReaderMutexLock l(&mu);
        file_wd = ASSERT_NO_ERRNO_AND_VALUE(
            InotifyAddWatch(ifd.get(), file, IN_ALL_EVENTS));
      }
      sched_yield();
    }
  });

  // Modify attributes on dir and file.
  ScopedThread stats([&] {
    int fd, dir_fd;
    {
      absl::ReaderMutexLock l(&mu);
      ASSERT_THAT(fd = open(file.c_str(), O_RDONLY), SyscallSucceeds());
    }
    ASSERT_THAT(dir_fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY),
                SyscallSucceeds());
    const struct timeval times[2] = {{1, 0}, {2, 0}};

    for (auto start = absl::Now(); absl::Now() - start < runtime;) {
      {
        absl::ReaderMutexLock l(&mu);
        EXPECT_THAT(utimes(file.c_str(), times), SyscallSucceeds());
      }
      EXPECT_THAT(futimes(fd, times), SyscallSucceeds());
      EXPECT_THAT(utimes(dir.c_str(), times), SyscallSucceeds());
      EXPECT_THAT(futimes(dir_fd, times), SyscallSucceeds());
      sched_yield();
    }
  });

  // Modify extended attributes on dir and file.
  ScopedThread xattrs([&] {
    // TODO(gvisor.dev/issue/1636): Support extended attributes in runsc gofer.
    if (!IsRunningOnGvisor()) {
      int fd;
      {
        absl::ReaderMutexLock l(&mu);
        ASSERT_THAT(fd = open(file.c_str(), O_RDONLY), SyscallSucceeds());
      }

      const char* name = "user.test";
      int val = 123;
      for (auto start = absl::Now(); absl::Now() - start < runtime;) {
        {
          absl::ReaderMutexLock l(&mu);
          ASSERT_THAT(
              setxattr(file.c_str(), name, &val, sizeof(val), /*flags=*/0),
              SyscallSucceeds());
          ASSERT_THAT(removexattr(file.c_str(), name), SyscallSucceeds());
        }

        ASSERT_THAT(fsetxattr(fd, name, &val, sizeof(val), /*flags=*/0),
                    SyscallSucceeds());
        ASSERT_THAT(fremovexattr(fd, name), SyscallSucceeds());
        sched_yield();
      }
    }
  });

  // Read and write file's contents. Read and write dir's entries.
  ScopedThread read_write([&] {
    int fd;
    {
      absl::ReaderMutexLock l(&mu);
      ASSERT_THAT(fd = open(file.c_str(), O_RDWR), SyscallSucceeds());
    }
    for (auto start = absl::Now(); absl::Now() - start < runtime;) {
      int val = 123;
      ASSERT_THAT(write(fd, &val, sizeof(val)), SyscallSucceeds());
      ASSERT_THAT(read(fd, &val, sizeof(val)), SyscallSucceeds());
      TempPath new_file =
          ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir));
      ASSERT_NO_ERRNO(ListDir(dir, false));
      new_file.reset();
      sched_yield();
    }
  });

  // Rename file.
  for (auto start = absl::Now(); absl::Now() - start < runtime;) {
    const std::string new_path = NewTempAbsPathInDir(dir);
    {
      absl::WriterMutexLock l(&mu);
      ASSERT_THAT(rename(file.c_str(), new_path.c_str()), SyscallSucceeds());
      file = new_path;
    }
    sched_yield();
  }
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
