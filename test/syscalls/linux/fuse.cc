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
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "test/util/cleanup.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
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
  if (IsRunningOnGvisor()) {
    EXPECT_THAT(ioctl(fd2.get(), FUSE_DEV_IOC_CLONE, &fd1_num),
                SyscallFailsWithErrno(EINVAL));
  } else {
    // Linux changed this error to EPERM; stable backports make a version
    // threshold unreliable. Keep accepting EINVAL on older kernels.
    // https://github.com/torvalds/linux/commit/da6fcc6db
    EXPECT_THAT(ioctl(fd2.get(), FUSE_DEV_IOC_CLONE, &fd1_num),
                ::testing::AnyOf(SyscallFailsWithErrno(EINVAL),
                                 SyscallFailsWithErrno(EPERM)));
  }
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

}  // namespace
}  // namespace testing
}  // namespace gvisor
