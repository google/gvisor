// Copyright 2023 The gVisor Authors.
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
#include <linux/fuse.h>
#include <linux/stat.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

using ::testing::Ge;

// Old versions of glibc do not define this flag.
#ifndef AT_STATX_DONT_SYNC
#define AT_STATX_DONT_SYNC 0x4000
#endif  // AT_STATX_DONT_SYNC

namespace gvisor {
namespace testing {

namespace {

int fallocate(int fd, int mode, off_t offset, off_t len) {
  return RetryEINTR(syscall)(__NR_fallocate, fd, mode, offset, len);
}

void FuseRespond(int fd, uint64_t unique, const void* payload = nullptr,
                 size_t size = 0, int error = 0) {
  fuse_out_header out_hdr = {
      .len = static_cast<uint32_t>(sizeof(out_hdr) + size),
      .error = error,
      .unique = unique,
  };
  struct iovec iov[] = {
      {.iov_base = &out_hdr, .iov_len = sizeof(out_hdr)},
      {.iov_base = const_cast<void*>(payload), .iov_len = size},
  };
  ASSERT_THAT(writev(fd, iov, payload ? 2 : 1),
              SyscallSucceedsWithValue(out_hdr.len));
}

void FuseInit(int fd) {
  alignas(fuse_in_header) char req_buf[FUSE_MIN_READ_BUFFER];
  ASSERT_THAT(read(fd, req_buf, sizeof(req_buf)),
              SyscallSucceedsWithValue(Ge(sizeof(fuse_in_header))));

  fuse_in_header* in_hdr = reinterpret_cast<fuse_in_header*>(req_buf);
  ASSERT_EQ(in_hdr->opcode, FUSE_INIT);

  fuse_init_out out_payload = {
      .major = FUSE_KERNEL_VERSION,
      .minor = FUSE_KERNEL_MINOR_VERSION,
  };
  FuseRespond(fd, in_hdr->unique, &out_payload, sizeof(out_payload));
}

// Takes ownership of an initialized device. The callback returns false to stop
// serving requests; a fatal assertion also stops the loop. Closing the device
// on exit aborts any client still waiting for a reply.
void RunFuseServer(
    int device_fd, int stop_fd,
    const std::function<bool(int, const fuse_in_header&)>& respond) {
  const FileDescriptor fd(device_fd);
  ASSERT_THAT(fcntl(fd.get(), F_SETFL, O_NONBLOCK), SyscallSucceeds());
  alignas(fuse_in_header) char req_buf[65536];
  while (!::testing::Test::HasFatalFailure()) {
    struct pollfd fds[] = {
        {.fd = fd.get(), .events = POLLIN},
        {.fd = stop_fd, .events = POLLIN},
    };
    ASSERT_THAT(RetryEINTR(poll)(fds, 2, -1), SyscallSucceeds());
    if (fds[1].revents & POLLIN) break;
    ssize_t res = RetryEINTR(read)(fd.get(), req_buf, sizeof(req_buf));
    if (res < 0 && errno == EAGAIN) continue;
    ASSERT_THAT(res, SyscallSucceedsWithValue(Ge(sizeof(fuse_in_header))));
    const auto& in = *reinterpret_cast<fuse_in_header*>(req_buf);
    if (in.opcode == FUSE_FORGET) continue;
    SCOPED_TRACE(absl::StrFormat("FUSE opcode %u", in.opcode));
    if (!respond(fd.get(), in)) break;
  }
}

TEST(FuseTest, RejectBadInit) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR, 0));

  auto mount_point = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mount_opts =
      absl::StrFormat("fd=%d,user_id=0,group_id=0,rootmode=40000", fd.get());
  auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("fuse", mount_point.path(), "fuse", MS_NODEV | MS_NOSUID,
            mount_opts, 0 /* umountflags */));

  // Read the init request so that we have the correct unique ID.
  alignas(fuse_in_header) char req_buf[FUSE_MIN_READ_BUFFER];
  ASSERT_THAT(read(fd.get(), req_buf, sizeof(req_buf)),
              SyscallSucceedsWithValue(Ge(sizeof(fuse_in_header))));

  fuse_out_header resp;
  resp.len = sizeof(resp) - 1;
  resp.error = 0;
  resp.unique = reinterpret_cast<fuse_in_header*>(req_buf)->unique;

  ASSERT_THAT(write(fd.get(), reinterpret_cast<char*>(&resp), sizeof(resp)),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FuseTest, CloneDevice) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(IsRunningWithSaveRestore());

  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR));

  auto mount_point = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mount_opts =
      absl::StrFormat("fd=%d,user_id=0,group_id=0,rootmode=40000", fd1.get());
  auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("fuse", mount_point.path(), "fuse", MS_NODEV | MS_NOSUID,
            mount_opts, 0 /* umountflags */));
  FuseInit(fd1.get());

  const FileDescriptor fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR));
  int fd1_num = fd1.get();
  ASSERT_THAT(ioctl(fd2.get(), FUSE_DEV_IOC_CLONE, &fd1_num),
              SyscallSucceeds());

  ScopedThread fuse_server = ScopedThread([&] {
    // Send stat reply from both FUSE servers.
    for (int fd : {fd1.get(), fd2.get()}) {
      // Read the stat request.
      alignas(fuse_in_header) char req_buf[4096 * 4];
      ASSERT_THAT(read(fd, req_buf, sizeof(req_buf)),
                  SyscallSucceedsWithValue(Ge(sizeof(fuse_in_header))));

      fuse_in_header* in_hdr = reinterpret_cast<fuse_in_header*>(req_buf);
      ASSERT_EQ(in_hdr->opcode, FUSE_GETATTR);

      // Send stat reply.
      fuse_out_header out_hdr;
      out_hdr.error = 0;
      out_hdr.unique = in_hdr->unique;
      fuse_attr_out out_payload = {};
      out_payload.attr.mode = S_IFDIR | 0755;
      out_payload.attr.nlink = 1;
      out_payload.attr.uid = 0;
      out_payload.attr.gid = 0;
      out_payload.attr.size = fd;
      out_payload.attr.atime = 0;
      out_payload.attr.mtime = 0;
      out_payload.attr.ctime = 0;

      struct iovec iov[] = {
          {.iov_base = &out_hdr, .iov_len = sizeof(out_hdr)},
          {.iov_base = &out_payload, .iov_len = sizeof(out_payload)},
      };
      out_hdr.len = sizeof(out_hdr) + sizeof(out_payload);

      ASSERT_THAT(
          writev(fd, iov, 2),
          SyscallSucceedsWithValue(sizeof(out_hdr) + sizeof(out_payload)));
    }
  });

  // Check if filesystem is responsive by stat'ing root. Both FUSE servers
  // should be able to respond.
  struct stat st;
  EXPECT_THAT(stat(mount_point.path().c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_size, fd1.get());
  EXPECT_THAT(stat(mount_point.path().c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_size, fd2.get());

  fuse_server.Join();
}

TEST(FuseTest, CloneToConnectedDeviceFails) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR));

  auto mount_point = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mount_opts =
      absl::StrFormat("fd=%d,user_id=0,group_id=0,rootmode=40000", fd1.get());
  auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("fuse", mount_point.path(), "fuse", MS_NODEV | MS_NOSUID,
            mount_opts, 0 /* umountflags */));
  FuseInit(fd1.get());

  int fd1_num = fd1.get();
  EXPECT_THAT(ioctl(fd1.get(), FUSE_DEV_IOC_CLONE, &fd1_num),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FuseTest, CloneFromUnconnectedDeviceFails) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR));

  const FileDescriptor fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR));

  int fd1_num = fd1.get();
  EXPECT_THAT(ioctl(fd2.get(), FUSE_DEV_IOC_CLONE, &fd1_num),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FuseTest, Fallocate) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(IsRunningWithSaveRestore());

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR));

  auto mount_point = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mount_opts =
      absl::StrFormat("fd=%d,user_id=0,group_id=0,rootmode=40000", fd.get());
  auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("fuse", mount_point.path(), "fuse", MS_NODEV | MS_NOSUID,
            mount_opts, 0 /* umountflags */));
  ASSERT_NO_FATAL_FAILURE(FuseInit(fd.get()));
  const FileDescriptor stop_fd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_CLOEXEC));

  constexpr uint64_t kIno = 42;
  constexpr uint64_t kBlocks = 8;

  ScopedThread fuse_server([&, server_fd = fd.release()] {
    RunFuseServer(
        server_fd, stop_fd.get(), [&](int fd, const fuse_in_header& in) {
          if (in.opcode == FUSE_LOOKUP) {
            fuse_entry_out out = {.nodeid = 2,
                                  .generation = 1,
                                  .entry_valid = 1,
                                  .attr_valid = 1};
            out.attr = {.ino = kIno,
                        .blocks = kBlocks,
                        .mode = S_IFREG | 0644,
                        .nlink = 1};
            FuseRespond(fd, in.unique, &out, sizeof(out));
          } else if (in.opcode == FUSE_OPEN) {
            fuse_open_out out = {.fh = 1};
            FuseRespond(fd, in.unique, &out, sizeof(out));
          } else if (in.opcode == FUSE_GETATTR) {
            fuse_attr_out out = {.attr_valid = 1};
            out.attr = {
                .ino = in.nodeid == 1 ? 1 : kIno,
                .blocks = in.nodeid == 1 ? 0 : kBlocks,
                .mode = in.nodeid == 1 ? S_IFDIR | 0755U : S_IFREG | 0644U,
                .nlink = 1};
            FuseRespond(fd, in.unique, &out, sizeof(out));
          } else if (in.opcode == FUSE_ACCESS || in.opcode == FUSE_FALLOCATE ||
                     in.opcode == FUSE_FLUSH || in.opcode == FUSE_RELEASE) {
            FuseRespond(fd, in.unique);
          } else {
            FuseRespond(fd, in.unique, nullptr, 0, -ENOSYS);
          }
          return in.opcode != FUSE_RELEASE;
        });
  });
  // An assertion before a file is opened cannot rely on a RELEASE request to
  // stop the server. Wake its poll before ScopedThread's destructor joins it.
  Cleanup stop_server([&] {
    const uint64_t stop = 1;
    EXPECT_THAT(RetryEINTR(write)(stop_fd.get(), &stop, sizeof(stop)),
                SyscallSucceedsWithValue(sizeof(stop)));
  });

  std::string file_path = JoinPath(mount_point.path(), "testfile");
  FileDescriptor file_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file_path, O_RDWR, 0));

  struct stat st_before = {};
  EXPECT_THAT(fstat(file_fd.get(), &st_before), SyscallSucceeds());
  EXPECT_EQ(st_before.st_size, 0);

  EXPECT_THAT(fallocate(file_fd.get(), 0, 5, 1), SyscallSucceeds());

  // Without writeback caching, a normal fstat refreshes attributes from the
  // server. Inspect the kernel's size update without requesting that refresh.
  constexpr unsigned int kStatMask =
      STATX_SIZE | STATX_TYPE | STATX_INO | STATX_BLOCKS;
  struct statx st = {};
  EXPECT_THAT(
      RetryEINTR(syscall)(__NR_statx, file_fd.get(), "",
                          AT_EMPTY_PATH | AT_STATX_DONT_SYNC, kStatMask, &st),
      SyscallSucceeds());
  EXPECT_EQ(st.stx_mask & kStatMask, kStatMask);
  EXPECT_EQ(st.stx_mode & S_IFMT, S_IFREG);
  EXPECT_EQ(st.stx_size, 6);
  EXPECT_EQ(st.stx_ino, kIno);
  EXPECT_EQ(st.stx_blocks, kBlocks);

  file_fd.reset();
  fuse_server.Join();
}

TEST(FuseTest, AccessUnsupported) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(IsRunningWithSaveRestore());

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR));
  auto mount_point = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mount_opts =
      absl::StrFormat("fd=%d,user_id=0,group_id=0,rootmode=40000", fd.get());
  auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("fuse", mount_point.path(), "fuse", MS_NODEV | MS_NOSUID,
            mount_opts, 0 /* umountflags */));
  ASSERT_NO_FATAL_FAILURE(FuseInit(fd.get()));
  const FileDescriptor stop_fd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_CLOEXEC));

  int access_requests = 0;
  ScopedThread fuse_server([&, server_fd = fd.release()] {
    RunFuseServer(
        server_fd, stop_fd.get(), [&](int fd, const fuse_in_header& in) {
          if (in.opcode == FUSE_ACCESS) {
            ++access_requests;
            // A real denial must not disable ACCESS. ENOSYS disables it for the
            // connection; reply to unexpected later requests so failures cannot
            // hang.
            const int error = access_requests == 2 ? ENOSYS : EACCES;
            FuseRespond(fd, in.unique, nullptr, 0, -error);
          } else if (in.opcode == FUSE_LOOKUP) {
            fuse_entry_out out = {.nodeid = 2,
                                  .generation = 1,
                                  .entry_valid = 1,
                                  .attr_valid = 1};
            out.attr = {.ino = 2, .mode = S_IFREG | 0644, .nlink = 1};
            FuseRespond(fd, in.unique, &out, sizeof(out));
          } else if (in.opcode == FUSE_GETATTR) {
            fuse_attr_out out = {.attr_valid = 1};
            out.attr = {
                .ino = in.nodeid,
                .mode = in.nodeid == 1 ? S_IFDIR | 0755U : S_IFREG | 0644U,
                .nlink = 1};
            FuseRespond(fd, in.unique, &out, sizeof(out));
          } else {
            FuseRespond(fd, in.unique, nullptr, 0, -ENOSYS);
          }
          return true;
        });
  });
  Cleanup stop_server([&] {
    const uint64_t stop = 1;
    EXPECT_THAT(RetryEINTR(write)(stop_fd.get(), &stop, sizeof(stop)),
                SyscallSucceedsWithValue(sizeof(stop)));
  });

  EXPECT_THAT(access(mount_point.path().c_str(), R_OK),
              SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(access(mount_point.path().c_str(), R_OK), SyscallSucceeds());
  // The cached capability applies to another inode and a different mask.
  const std::string file_path = JoinPath(mount_point.path(), "testfile");
  EXPECT_THAT(access(file_path.c_str(), W_OK), SyscallSucceeds());
}

TEST(FuseTest, LookupUpdatesInode) {
  SKIP_IF(absl::NullSafeStringView(getenv("GVISOR_FUSE_TEST")) != "TRUE");
  const std::string kFileData = "May thy knife chip and shatter.\n";
  TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDONLY));
  std::vector<char> buf(kFileData.size());
  ASSERT_THAT(ReadFd(fd.get(), buf.data(), kFileData.size()),
              SyscallSucceedsWithValue(kFileData.size()));

  ASSERT_THAT(unlink(JoinPath("/fuse", Basename(path.path())).c_str()),
              SyscallSucceeds());

  EXPECT_THAT(access(path.path().c_str(), O_RDONLY),
              SyscallFailsWithErrno(ENOENT));
}

// Tests for the semantics described in the "Interrupting filesystem
// operations" section of Linux's Documentation/filesystems/fuse.rst. In these
// tests, the test itself acts as the FUSE server, while stat(2) on the mount
// point (which results in a FUSE_GETATTR request) is used as the interrupted
// filesystem operation.

// Timeout used when waiting for a FUSE request that is expected to arrive.
constexpr int kRequestTimeoutMs = 10000;

// Time to wait before concluding that something that isn't expected to happen
// (e.g. a FUSE request being queued or a syscall returning) didn't happen.
constexpr absl::Duration kNegativeTimeout = absl::Milliseconds(200);

// The bit set in the unique ID of FUSE_INTERRUPT requests. FUSE_INT_REQ_BIT
// is not defined by older kernel headers.
constexpr uint64_t kFuseIntReqBit = 1;

// A buffer for reading a single FUSE request.
struct FuseRequest {
  alignas(fuse_in_header) char buf[FUSE_MIN_READ_BUFFER];

  const fuse_in_header* hdr() const {
    return reinterpret_cast<const fuse_in_header*>(buf);
  }

  template <typename T>
  const T* payload() const {
    return reinterpret_cast<const T*>(buf + sizeof(fuse_in_header));
  }
};

// Waits for a request to become available on the FUSE device fd and reads
// it into req.
void ReadFuseRequest(int fd, FuseRequest* req) {
  struct pollfd pfd = {.fd = fd, .events = POLLIN};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, kRequestTimeoutMs),
              SyscallSucceedsWithValue(1));
  ASSERT_THAT(read(fd, req->buf, sizeof(req->buf)),
              SyscallSucceedsWithValue(Ge(sizeof(fuse_in_header))));
}

// Waits for a request to become available on the FUSE device fd without
// reading it.
void WaitForFuseRequest(int fd) {
  struct pollfd pfd = {.fd = fd, .events = POLLIN};
  ASSERT_THAT(RetryEINTR(poll)(&pfd, 1, kRequestTimeoutMs),
              SyscallSucceedsWithValue(1));
}

// Checks that no request becomes available on the FUSE device fd.
void ExpectNoFuseRequest(int fd) {
  struct pollfd pfd = {.fd = fd, .events = POLLIN};
  EXPECT_THAT(
      RetryEINTR(poll)(&pfd, 1, absl::ToInt64Milliseconds(kNegativeTimeout)),
      SyscallSucceedsWithValue(0));
}

// Checks that req is a FUSE_INTERRUPT request for the request with the given
// unique ID.
void ExpectInterruptRequest(const FuseRequest& req, uint64_t unique) {
  EXPECT_EQ(req.hdr()->opcode, FUSE_INTERRUPT);
  EXPECT_EQ(req.hdr()->len, sizeof(fuse_in_header) + sizeof(fuse_interrupt_in));
  EXPECT_EQ(req.hdr()->unique, unique | kFuseIntReqBit);
  EXPECT_EQ(req.payload<fuse_interrupt_in>()->unique, unique);
}

// Sends a successful reply to the FUSE_GETATTR request with the given unique
// ID.
void ReplyGetattr(int fd, uint64_t unique) {
  fuse_out_header out_hdr = {};
  out_hdr.unique = unique;
  fuse_attr_out out_payload = {};
  out_payload.attr.mode = S_IFDIR | 0755;
  out_payload.attr.nlink = 2;
  struct iovec iov[] = {
      {.iov_base = &out_hdr, .iov_len = sizeof(out_hdr)},
      {.iov_base = &out_payload, .iov_len = sizeof(out_payload)},
  };
  out_hdr.len = sizeof(out_hdr) + sizeof(out_payload);
  ASSERT_THAT(writev(fd, iov, 2), SyscallSucceedsWithValue(out_hdr.len));
}

// Sends an error reply with the given unique ID, which may refer to an
// ordinary request or to a FUSE_INTERRUPT request.
PosixError ReplyError(int fd, uint64_t unique, int err) {
  fuse_out_header out_hdr = {};
  out_hdr.len = sizeof(out_hdr);
  out_hdr.error = -err;
  out_hdr.unique = unique;
  if (write(fd, &out_hdr, sizeof(out_hdr)) != sizeof(out_hdr)) {
    return PosixError(errno, "write");
  }
  return NoError();
}

// A child process that performs a filesystem operation that results in a FUSE
// request. The child is killed when FuseClient is destroyed if it hasn't
// exited, so that test failures don't leave it blocked forever.
class FuseClient {
 public:
  enum class Op { kStat, kStatfs };

  FuseClient(const std::string& path, Op op) {
    const char* const p = path.c_str();
    pid_ = fork();
    if (pid_ == 0) {
      int ret;
      if (op == Op::kStatfs) {
        struct statfs st;
        ret = statfs(p, &st);
      } else {
        struct stat st;
        ret = stat(p, &st);
      }
      _exit(ret == 0 ? 0 : errno);
    }
    TEST_PCHECK(pid_ > 0);
  }

  ~FuseClient() {
    if (status_ < 0) {
      kill(pid_, SIGKILL);
      RetryEINTR(waitpid)(pid_, &status_, 0);
    }
  }

  FuseClient(const FuseClient&) = delete;
  FuseClient& operator=(const FuseClient&) = delete;

  pid_t pid() const { return pid_; }

  // Returns true if the operation has returned.
  bool Done() {
    int status;
    if (status_ < 0 && waitpid(pid_, &status, WNOHANG) == pid_) {
      status_ = status;
    }
    return status_ >= 0;
  }

  // Waits for the child to exit and returns its wait status.
  int WaitStatus() {
    if (status_ < 0) {
      TEST_PCHECK(RetryEINTR(waitpid)(pid_, &status_, 0) == pid_);
    }
    return status_;
  }

  // Waits for the operation to return, and returns 0 if it succeeded or its
  // errno otherwise.
  int Wait() {
    const int status = WaitStatus();
    TEST_CHECK_MSG(WIFEXITED(status), "client did not exit normally");
    return WEXITSTATUS(status);
  }

 private:
  pid_t pid_;
  int status_ = -1;
};

// Sends a successful reply to the FUSE_STATFS request with the given unique
// ID.
void ReplyStatfs(int fd, uint64_t unique) {
  fuse_out_header out_hdr = {};
  out_hdr.unique = unique;
  fuse_statfs_out out_payload = {};
  out_payload.st.bsize = 4096;
  out_payload.st.namelen = 255;
  out_payload.st.frsize = 4096;
  struct iovec iov[] = {
      {.iov_base = &out_hdr, .iov_len = sizeof(out_hdr)},
      {.iov_base = &out_payload, .iov_len = sizeof(out_payload)},
  };
  out_hdr.len = sizeof(out_hdr) + sizeof(out_payload);
  ASSERT_THAT(writev(fd, iov, 2), SyscallSucceedsWithValue(out_hdr.len));
}

// Fixture that mounts a FUSE filesystem served by the test itself.
class FuseServerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

    fd_ = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR));
    mount_point_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    auto mount_opts =
        absl::StrFormat("fd=%d,user_id=0,group_id=0,rootmode=40000", fd_.get());
    mount_ = ASSERT_NO_ERRNO_AND_VALUE(Mount("fuse", mount_point_.path(),
                                             "fuse", MS_NODEV | MS_NOSUID,
                                             mount_opts, 0 /* umountflags */));
    ASSERT_NO_FATAL_FAILURE(FuseInit(fd_.get()));
  }

  // Starts a stat(2) of the mount point in a child process and reads the
  // resulting FUSE_GETATTR request, returning its unique ID in unique.
  void StartStatAndReadRequest(std::unique_ptr<FuseClient>* client,
                               uint64_t* unique) {
    *client = StartClient(FuseClient::Op::kStat);
    FuseRequest req;
    ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &req));
    ASSERT_EQ(req.hdr()->opcode, FUSE_GETATTR);
    // Ordinary requests have even unique IDs.
    ASSERT_EQ(req.hdr()->unique & kFuseIntReqBit, uint64_t{0});
    *unique = req.hdr()->unique;
  }

  std::unique_ptr<FuseClient> StartClient(FuseClient::Op op) {
    return std::make_unique<FuseClient>(mount_point_.path(), op);
  }

  FileDescriptor fd_;
  TempPath mount_point_;
  Cleanup mount_;
};

class FuseInterruptTest : public FuseServerTest {
 protected:
  void SetUp() override {
    ASSERT_NO_FATAL_FAILURE(FuseServerTest::SetUp());
    if (IsSkipped()) {
      return;
    }

    // Install a non-fatal handler for SIGUSR1, which is used to interrupt
    // FUSE requests. SA_RESTART is deliberately not set.
    struct sigaction sa = {};
    sa.sa_handler = +[](int) {};
    sigemptyset(&sa.sa_mask);
    sigaction_ = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));
  }

  // Stops for checkpointing interrupt in-flight FUSE requests, which
  // interferes with these tests.
  const DisableSave ds_;
  Cleanup sigaction_;
};

// A signal interrupting a request that has been read by the server results
// in a FUSE_INTERRUPT request. The interrupted task keeps waiting for the
// reply, and an EINTR reply is returned to it.
TEST_F(FuseInterruptTest, InterruptSentRequest) {
  std::unique_ptr<FuseClient> client;
  uint64_t unique;
  ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client, &unique));

  ASSERT_THAT(kill(client->pid(), SIGUSR1), SyscallSucceeds());

  FuseRequest intr;
  ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &intr));
  ExpectInterruptRequest(intr, unique);

  // The interrupted operation must still be waiting for a reply.
  absl::SleepFor(kNegativeTimeout);
  EXPECT_FALSE(client->Done());

  // Honor the interrupt.
  ASSERT_NO_ERRNO(ReplyError(fd_.get(), unique, EINTR));
  EXPECT_EQ(client->Wait(), EINTR);
}

// The server may ignore FUSE_INTERRUPT requests and reply to the original
// request normally.
TEST_F(FuseInterruptTest, InterruptIgnored) {
  std::unique_ptr<FuseClient> client;
  uint64_t unique;
  ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client, &unique));

  ASSERT_THAT(kill(client->pid(), SIGUSR1), SyscallSucceeds());

  FuseRequest intr;
  ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &intr));
  ExpectInterruptRequest(intr, unique);

  ASSERT_NO_FATAL_FAILURE(ReplyGetattr(fd_.get(), unique));
  EXPECT_EQ(client->Wait(), 0);
}

// A signal interrupting a request that has not yet been read by the server
// results in a FUSE_INTERRUPT request being queued only once the original
// request has been read.
TEST_F(FuseInterruptTest, InterruptUnsentRequest) {
  auto client = StartClient(FuseClient::Op::kStat);

  // Wait until the request is queued, then interrupt it before reading it.
  ASSERT_NO_FATAL_FAILURE(WaitForFuseRequest(fd_.get()));
  ASSERT_THAT(kill(client->pid(), SIGUSR1), SyscallSucceeds());
  absl::SleepFor(kNegativeTimeout);
  EXPECT_FALSE(client->Done());

  // Even though it was interrupted, the original request is received first.
  FuseRequest req;
  ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &req));
  ASSERT_EQ(req.hdr()->opcode, FUSE_GETATTR);
  const uint64_t unique = req.hdr()->unique;

  FuseRequest intr;
  ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &intr));
  ExpectInterruptRequest(intr, unique);

  ASSERT_NO_ERRNO(ReplyError(fd_.get(), unique, EINTR));
  EXPECT_EQ(client->Wait(), EINTR);
}

// INTERRUPT requests take precedence over other requests.
TEST_F(FuseInterruptTest, InterruptTakesPrecedence) {
  std::unique_ptr<FuseClient> client1;
  uint64_t unique1;
  ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client1, &unique1));

  // Queue a second request, but don't read it. statfs(2) is used since gVisor
  // serializes FUSE_GETATTR requests for the same inode.
  auto client2 = StartClient(FuseClient::Op::kStatfs);
  ASSERT_NO_FATAL_FAILURE(WaitForFuseRequest(fd_.get()));

  // Interrupt the first request. The FUSE_INTERRUPT request must be received
  // before the second request.
  ASSERT_THAT(kill(client1->pid(), SIGUSR1), SyscallSucceeds());
  absl::SleepFor(kNegativeTimeout);

  FuseRequest intr;
  ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &intr));
  ExpectInterruptRequest(intr, unique1);

  FuseRequest req2;
  ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &req2));
  ASSERT_EQ(req2.hdr()->opcode, FUSE_STATFS);

  ASSERT_NO_ERRNO(ReplyError(fd_.get(), unique1, EINTR));
  ASSERT_NO_FATAL_FAILURE(ReplyStatfs(fd_.get(), req2.hdr()->unique));
  EXPECT_EQ(client1->Wait(), EINTR);
  EXPECT_EQ(client2->Wait(), 0);
}

// If the server replies to a FUSE_INTERRUPT request with EAGAIN, the
// FUSE_INTERRUPT request is requeued.
TEST_F(FuseInterruptTest, InterruptEAGAINRequeues) {
  std::unique_ptr<FuseClient> client;
  uint64_t unique;
  ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client, &unique));

  ASSERT_THAT(kill(client->pid(), SIGUSR1), SyscallSucceeds());

  FuseRequest intr;
  ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &intr));
  ExpectInterruptRequest(intr, unique);

  ASSERT_NO_ERRNO(ReplyError(fd_.get(), intr.hdr()->unique, EAGAIN));

  FuseRequest intr2;
  ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &intr2));
  ExpectInterruptRequest(intr2, unique);

  ASSERT_NO_ERRNO(ReplyError(fd_.get(), unique, EINTR));
  EXPECT_EQ(client->Wait(), EINTR);
}

// If the server replies to a FUSE_INTERRUPT request with ENOSYS, no further
// FUSE_INTERRUPT requests are sent, and signals no longer interrupt FUSE
// requests.
TEST_F(FuseInterruptTest, InterruptENOSYSDisablesInterrupts) {
  {
    std::unique_ptr<FuseClient> client;
    uint64_t unique;
    ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client, &unique));

    ASSERT_THAT(kill(client->pid(), SIGUSR1), SyscallSucceeds());

    FuseRequest intr;
    ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &intr));
    ExpectInterruptRequest(intr, unique);
    ASSERT_NO_ERRNO(ReplyError(fd_.get(), intr.hdr()->unique, ENOSYS));

    ASSERT_NO_FATAL_FAILURE(ReplyGetattr(fd_.get(), unique));
    EXPECT_EQ(client->Wait(), 0);
  }

  std::unique_ptr<FuseClient> client;
  uint64_t unique;
  ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client, &unique));

  ASSERT_THAT(kill(client->pid(), SIGUSR1), SyscallSucceeds());
  ExpectNoFuseRequest(fd_.get());
  EXPECT_FALSE(client->Done());

  ASSERT_NO_FATAL_FAILURE(ReplyGetattr(fd_.get(), unique));
  EXPECT_EQ(client->Wait(), 0);
}

// Invalid replies to FUSE_INTERRUPT requests are rejected.
TEST_F(FuseInterruptTest, InvalidInterruptReplies) {
  // Reply to an interrupt for a request that doesn't exist.
  EXPECT_THAT(ReplyError(fd_.get(), 0x7ffffff0 | kFuseIntReqBit, EAGAIN),
              PosixErrorIs(ENOENT, ::testing::_));

  std::unique_ptr<FuseClient> client;
  uint64_t unique;
  ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client, &unique));

  // EAGAIN for a request that was never interrupted.
  EXPECT_THAT(ReplyError(fd_.get(), unique | kFuseIntReqBit, EAGAIN),
              PosixErrorIs(EINVAL, ::testing::_));

  // Replies to interrupts must not have a payload.
  struct {
    fuse_out_header hdr;
    uint64_t payload;
  } reply = {};
  reply.hdr.len = sizeof(reply);
  reply.hdr.unique = unique | kFuseIntReqBit;
  EXPECT_THAT(write(fd_.get(), &reply, sizeof(reply)),
              SyscallFailsWithErrno(EINVAL));

  // None of the above affected the original request.
  ASSERT_NO_FATAL_FAILURE(ReplyGetattr(fd_.get(), unique));
  EXPECT_EQ(client->Wait(), 0);
}

// A fatal signal received before the request has been read by the server
// dequeues the request.
TEST_F(FuseInterruptTest, FatalSignalDequeuesUnsentRequest) {
  {
    auto killed = StartClient(FuseClient::Op::kStat);
    // Wait until the request is queued, then kill the client (by destroying
    // it) before reading the request.
    ASSERT_NO_FATAL_FAILURE(WaitForFuseRequest(fd_.get()));
  }

  // The request must have been dequeued.
  ExpectNoFuseRequest(fd_.get());

  // The connection is still usable.
  std::unique_ptr<FuseClient> client;
  uint64_t unique;
  ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client, &unique));
  ASSERT_NO_FATAL_FAILURE(ReplyGetattr(fd_.get(), unique));
  EXPECT_EQ(client->Wait(), 0);
}

// A fatal signal received after the request has been read by the server
// results in a FUSE_INTERRUPT request, and the server can still reply to the
// original request.
TEST_F(FuseInterruptTest, FatalSignalSentRequest) {
  std::unique_ptr<FuseClient> client;
  uint64_t unique;
  ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client, &unique));

  ASSERT_THAT(kill(client->pid(), SIGKILL), SyscallSucceeds());

  FuseRequest intr;
  ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &intr));
  ExpectInterruptRequest(intr, unique);

  ASSERT_NO_FATAL_FAILURE(ReplyGetattr(fd_.get(), unique));
  const int status = client->WaitStatus();
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << "status=" << status;
}

// Tests for FUSE requests that are in flight while the sandbox is
// checkpointed. gVisor tasks must return from syscalls in order to be
// checkpointed, so in-flight FUSE requests are abandoned and their syscalls
// restarted after the checkpoint. Checkpoints only occur in save/restore and
// save/resume test variants; otherwise (including on Linux), Checkpoint() is
// a no-op and the tests check ordinary request handling.
class FuseCheckpointTest : public FuseServerTest {
 protected:
  void SetUp() override {
    // In save variants, saves would otherwise also occur after every
    // successful syscall (e.g. right after the server reads a request),
    // making it impossible to predict which requests are abandoned.
    ds_.emplace();
    ASSERT_NO_FATAL_FAILURE(FuseServerTest::SetUp());
  }

  // Checkpoints the sandbox, if running in a save variant.
  void Checkpoint() {
    ds_.reset();
    MaybeSave();
    ds_.emplace();
  }

  // Called after Checkpoint() while the FUSE_GETATTR request with the given
  // unique ID, which the server has read, is outstanding. If a checkpoint
  // occurred, the request has been abandoned: a FUSE_INTERRUPT request for it
  // is received, followed by the FUSE_GETATTR request reissued by the
  // restarted stat(2), whose unique ID is stored in unique.
  void MaybeExpectRestartedRequest(uint64_t* unique) {
    struct pollfd pfd = {.fd = fd_.get(), .events = POLLIN};
    const int n =
        RetryEINTR(poll)(&pfd, 1, absl::ToInt64Milliseconds(kNegativeTimeout));
    ASSERT_THAT(n, SyscallSucceeds());
    if (n == 0) {
      // No checkpoint occurred.
      return;
    }

    FuseRequest intr;
    ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &intr));
    ExpectInterruptRequest(intr, *unique);

    FuseRequest req;
    ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &req));
    ASSERT_EQ(req.hdr()->opcode, FUSE_GETATTR);
    ASSERT_NE(req.hdr()->unique, *unique);

    // Replies to the abandoned request are rejected.
    EXPECT_THAT(ReplyError(fd_.get(), *unique, EINTR),
                PosixErrorIs(ENOENT, ::testing::_));
    *unique = req.hdr()->unique;
  }

  std::optional<DisableSave> ds_;
};

// A request that has not been read by the server when the sandbox is
// checkpointed is transparently resent after the checkpoint, exactly once.
TEST_F(FuseCheckpointTest, UnsentRequest) {
  auto client = StartClient(FuseClient::Op::kStat);

  // Wait until the request is queued, then checkpoint before reading it.
  ASSERT_NO_FATAL_FAILURE(WaitForFuseRequest(fd_.get()));
  Checkpoint();

  FuseRequest req;
  ASSERT_NO_FATAL_FAILURE(ReadFuseRequest(fd_.get(), &req));
  ASSERT_EQ(req.hdr()->opcode, FUSE_GETATTR);
  ASSERT_NO_FATAL_FAILURE(ReplyGetattr(fd_.get(), req.hdr()->unique));

  // The interrupted stat(2) must not fail with EINTR.
  EXPECT_EQ(client->Wait(), 0);
  // The request was not sent twice.
  ExpectNoFuseRequest(fd_.get());
}

// A request that has been read by the server when the sandbox is checkpointed
// is interrupted and abandoned, and the restarted syscall sends it again.
TEST_F(FuseCheckpointTest, SentRequest) {
  std::unique_ptr<FuseClient> client;
  uint64_t unique;
  ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client, &unique));

  Checkpoint();
  ASSERT_NO_FATAL_FAILURE(MaybeExpectRestartedRequest(&unique));

  ExpectNoFuseRequest(fd_.get());
  EXPECT_FALSE(client->Done());

  ASSERT_NO_FATAL_FAILURE(ReplyGetattr(fd_.get(), unique));
  // The interrupted stat(2) must not fail with EINTR.
  EXPECT_EQ(client->Wait(), 0);
}

// As above, but with multiple checkpoints while the server holds the request.
// Requests reissued by the restarted syscall are not read by the server
// before the next checkpoint, so they are dropped rather than interrupted.
TEST_F(FuseCheckpointTest, SentRequestMultipleCheckpoints) {
  std::unique_ptr<FuseClient> client;
  uint64_t unique;
  ASSERT_NO_FATAL_FAILURE(StartStatAndReadRequest(&client, &unique));

  for (int i = 0; i < 3; i++) {
    Checkpoint();
    // Give the client time to restart and reissue the request before the
    // next save, so that the reissued request is abandoned again. This only
    // affects coverage, not correctness.
    absl::SleepFor(absl::Milliseconds(50));
  }
  ASSERT_NO_FATAL_FAILURE(MaybeExpectRestartedRequest(&unique));

  ExpectNoFuseRequest(fd_.get());
  EXPECT_FALSE(client->Done());

  ASSERT_NO_FATAL_FAILURE(ReplyGetattr(fd_.get(), unique));
  EXPECT_EQ(client->Wait(), 0);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
