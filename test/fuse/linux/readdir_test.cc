// Copyright 2020 The gVisor Authors.
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fuse.h>
#include <linux/unistd.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"
#include "test/fuse/linux/fuse_base.h"
#include "test/util/fuse_util.h"
#include "test/util/test_util.h"

#define FUSE_NAME_OFFSET offsetof(struct fuse_dirent, name)
#define FUSE_DIRENT_ALIGN(x) \
  (((x) + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))
#define FUSE_DIRENT_SIZE(d) FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)

namespace gvisor {
namespace testing {

namespace {

class ReaddirTest : public FuseTest {
 public:
  void fill_fuse_dirent(char *buf, const char *name, uint64_t ino) {
    size_t namelen = strlen(name);
    size_t entlen = FUSE_NAME_OFFSET + namelen;
    size_t entlen_padded = FUSE_DIRENT_ALIGN(entlen);
    struct fuse_dirent *dirent;

    dirent = reinterpret_cast<struct fuse_dirent *>(buf);
    dirent->ino = ino;
    dirent->namelen = namelen;
    memcpy(dirent->name, name, namelen);
    memset(dirent->name + namelen, 0, entlen_padded - entlen);
  }

 protected:
  const std::string test_dir_name_ = "test_dir";
};

TEST_F(ReaddirTest, SingleEntry) {
  const std::string test_dir_path =
      JoinPath(mount_point_.path().c_str(), test_dir_name_);

  const uint64_t ino_dir = 1024;
  // We need to make sure the test dir is a directory that can be found.
  mode_t expected_mode =
      S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
  struct fuse_attr dir_attr = {
      .ino = ino_dir,
      .size = 512,
      .blocks = 4,
      .mode = expected_mode,
      .blksize = 4096,
  };

  // We need to make sure the test dir is a directory that can be found.
  struct fuse_out_header lookup_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out),
  };
  struct fuse_entry_out lookup_payload = {
      .nodeid = 1,
      .entry_valid = true,
      .attr_valid = true,
      .attr = dir_attr,
  };

  struct fuse_out_header open_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
  };
  struct fuse_open_out open_payload = {
      .fh = 1,
  };
  auto iov_out = FuseGenerateIovecs(lookup_header, lookup_payload);
  SetServerResponse(FUSE_LOOKUP, iov_out);

  iov_out = FuseGenerateIovecs(open_header, open_payload);
  SetServerResponse(FUSE_OPENDIR, iov_out);

  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_dir_path.c_str(), O_RDONLY));

  // The open command makes two syscalls. Lookup the dir file and open.
  // We don't need to inspect those headers in this test.
  SkipServerActualRequest();  // LOOKUP.
  SkipServerActualRequest();  // OPENDIR.

  // Readdir test code.
  std::string dot = ".";
  std::string dot_dot = "..";
  std::string test_file = "testFile";

  // Figure out how many dirents to send over and allocate them appropriately.
  // Each dirent has a dynamic name and a static metadata part. The dirent size
  // is aligned to being a multiple of 8.
  size_t dot_file_dirent_size =
      FUSE_DIRENT_ALIGN(dot.length() + FUSE_NAME_OFFSET);
  size_t dot_dot_file_dirent_size =
      FUSE_DIRENT_ALIGN(dot_dot.length() + FUSE_NAME_OFFSET);
  size_t test_file_dirent_size =
      FUSE_DIRENT_ALIGN(test_file.length() + FUSE_NAME_OFFSET);

  // Create an appropriately sized payload.
  size_t readdir_payload_size =
      test_file_dirent_size + dot_file_dirent_size + dot_dot_file_dirent_size;
  std::vector<char> readdir_payload_vec(readdir_payload_size);
  char *readdir_payload = readdir_payload_vec.data();

  // Use fake ino for other directories.
  fill_fuse_dirent(readdir_payload, dot.c_str(), ino_dir - 2);
  fill_fuse_dirent(readdir_payload + dot_file_dirent_size, dot_dot.c_str(),
                   ino_dir - 1);
  fill_fuse_dirent(
      readdir_payload + dot_file_dirent_size + dot_dot_file_dirent_size,
      test_file.c_str(), ino_dir);

  struct fuse_out_header readdir_header = {
      .len = uint32_t(sizeof(struct fuse_out_header) + readdir_payload_size),
  };
  struct fuse_out_header readdir_header_break = {
      .len = uint32_t(sizeof(struct fuse_out_header)),
  };

  iov_out = FuseGenerateIovecs(readdir_header, readdir_payload_vec);
  SetServerResponse(FUSE_READDIR, iov_out);

  iov_out = FuseGenerateIovecs(readdir_header_break);
  SetServerResponse(FUSE_READDIR, iov_out);

  std::vector<char> buf(4090, 0);
  int nread, off = 0, i = 0;
  EXPECT_THAT(
      nread = syscall(__NR_getdents64, fd.get(), buf.data(), buf.size()),
      SyscallSucceeds());
  for (; off < nread;) {
    struct dirent64 *ent = (struct dirent64 *)(buf.data() + off);
    off += ent->d_reclen;
    switch (i++) {
      case 0:
        EXPECT_EQ(std::string(ent->d_name), dot);
        break;
      case 1:
        EXPECT_EQ(std::string(ent->d_name), dot_dot);
        break;
      case 2:
        EXPECT_EQ(std::string(ent->d_name), test_file);
        break;
    }
  }

  EXPECT_THAT(
      nread = syscall(__NR_getdents64, fd.get(), buf.data(), buf.size()),
      SyscallSucceedsWithValue(0));

  SkipServerActualRequest();  // READDIR.
  SkipServerActualRequest();  // READDIR with no data.

  // Clean up.
  fd.reset(-1);

  struct fuse_in_header in_header;
  struct fuse_release_in in_payload;

  auto iov_in = FuseGenerateIovecs(in_header, in_payload);
  GetServerActualRequest(iov_in);
  EXPECT_EQ(in_header.len, sizeof(in_header) + sizeof(in_payload));
  EXPECT_EQ(in_header.opcode, FUSE_RELEASEDIR);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
