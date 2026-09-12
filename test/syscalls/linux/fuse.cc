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
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
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

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR));

  auto mount_point = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mount_opts =
      absl::StrFormat("fd=%d,user_id=0,group_id=0,rootmode=40000", fd.get());
  auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("fuse", mount_point.path(), "fuse", MS_NODEV | MS_NOSUID,
            mount_opts, 0 /* umountflags */));
  FuseInit(fd.get());

  ScopedThread fuse_server = ScopedThread([&] {
    alignas(fuse_in_header) char req_buf[65536];
    while (true) {
      ssize_t res = read(fd.get(), req_buf, sizeof(req_buf));
      if (res <= 0) break;
      auto* in = reinterpret_cast<fuse_in_header*>(req_buf);
      if (in->opcode == FUSE_FORGET) continue;

      if (in->opcode == FUSE_LOOKUP) {
        fuse_entry_out out = {
            .nodeid = 2, .generation = 1, .entry_valid = 1, .attr_valid = 1};
        out.attr = {.ino = 2, .mode = S_IFREG | 0644, .nlink = 1};
        FuseRespond(fd.get(), in->unique, &out, sizeof(out));
      } else if (in->opcode == FUSE_OPEN) {
        fuse_open_out out = {.fh = 1};
        FuseRespond(fd.get(), in->unique, &out, sizeof(out));
      } else if (in->opcode == FUSE_GETATTR) {
        fuse_attr_out out = {.attr_valid = 1};
        out.attr = {.ino = in->nodeid,
                    .mode = in->nodeid == 1 ? S_IFDIR | 0755U : S_IFREG | 0644U,
                    .nlink = 1};
        FuseRespond(fd.get(), in->unique, &out, sizeof(out));
      } else if (in->opcode == FUSE_FALLOCATE) {
        FuseRespond(fd.get(), in->unique);
      } else if (in->opcode == FUSE_RELEASE) {
        FuseRespond(fd.get(), in->unique);
        break;
      } else {
        FuseRespond(fd.get(), in->unique);
      }
    }
  });

  std::string file_path = JoinPath(mount_point.path(), "testfile");
  FileDescriptor file_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file_path, O_RDWR, 0));

  struct stat st_before;
  EXPECT_THAT(fstat(file_fd.get(), &st_before), SyscallSucceeds());

  EXPECT_THAT(fallocate(file_fd.get(), 0, 5, 1), SyscallSucceeds());

  struct stat st;
  EXPECT_THAT(fstat(file_fd.get(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_size, 6);
  EXPECT_GT(st.st_mtime, 0);
  EXPECT_GT(st.st_ctime, 0);

  file_fd.reset();
  fuse_server.Join();
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
