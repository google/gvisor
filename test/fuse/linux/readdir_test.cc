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

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/fuse.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/test_util.h"
#include "test/util/fuse_util.h"
#include "test/util/fs_util.h"

#include "fuse_base.h"

#define FUSE_NAME_OFFSET offsetof(struct fuse_dirent, name)
#define FUSE_DIRENT_ALIGN(x) \
	(((x) + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))
#define FUSE_DIRENT_SIZE(d) \
	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)

namespace gvisor {
namespace testing {

namespace {

  class ReaddirTest : public FuseTest {
   public:
    void fill_fuse_dirent(char* buf, const char *name) {
      size_t namelen = strlen(name);
      size_t entlen = FUSE_NAME_OFFSET + namelen;
      size_t entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	  struct fuse_dirent *dirent;

      dirent = (struct fuse_dirent*) buf;
      dirent->namelen = namelen;
      memcpy(dirent->name, name, namelen);
      memset(dirent->name + namelen, 0, entlen_padded - entlen);
    }
  };

TEST_F(ReaddirTest, SingleEntry) {
  const std::string test_dir_path = JoinPath(kMountPoint, "testDir");
  struct iovec iov_out[2];

  // We need to make sure the test dir is a directory that can be found.
  mode_t expected_mode = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
  struct fuse_attr dir_attr = {
      .ino = 1,
      .size = 512,
      .blocks = 4,
      .mode = expected_mode,
      .blksize = 4096,
  };
  struct fuse_out_header stat_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out),
  };

  struct fuse_attr_out stat_payload = {
      .attr_valid_nsec = 2,
      .attr = dir_attr,
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
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, lookup_header, lookup_payload);
  SetServerResponse(FUSE_LOOKUP, iov_out, 2);
  
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, open_header, open_payload);
  SetServerResponse(FUSE_OPENDIR, iov_out, 2);
  
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, stat_header, stat_payload);
  SetServerResponse(FUSE_GETATTR, iov_out, 2);

  DIR *dir = opendir(test_dir_path.c_str());

  // The opendir command makes three syscalls. Lookup the dir file, stat it and
  // open.
  // We don't need to inspect those headers in this test.
  SkipServerActualRequest(); // LOOKUP.
  SkipServerActualRequest(); // GETATTR.
  SkipServerActualRequest(); // OPENDIR.

  // Readdir test code.
  std::string dot = ".";
  std::string dot_dot = "..";
  std::string test_file = "testFile";

  // Figure out how many dirents to send over and allocate them appropriately.
  // Each dirent has a dynamic name and a static metadata part. The dirent size
  // is aligned to being a multiple of 8.
  size_t dot_file_dirent_size = FUSE_DIRENT_ALIGN(dot.length() + FUSE_NAME_OFFSET);
  size_t dot_dot_file_dirent_size = FUSE_DIRENT_ALIGN(dot_dot.length() + FUSE_NAME_OFFSET);
  size_t test_file_dirent_size = FUSE_DIRENT_ALIGN(test_file.length() + FUSE_NAME_OFFSET);

  
  // Create an appropriately sized payload.
  char readdir_payload[test_file_dirent_size + dot_file_dirent_size + dot_dot_file_dirent_size];

  fill_fuse_dirent(readdir_payload, dot.c_str());
  fill_fuse_dirent(readdir_payload + dot_file_dirent_size, dot_dot.c_str());
  fill_fuse_dirent(readdir_payload + dot_file_dirent_size + dot_dot_file_dirent_size, test_file.c_str());


  struct fuse_out_header readdir_header = {
      .len = uint32_t(sizeof(struct fuse_out_header) + sizeof(readdir_payload)),
  };
  struct fuse_out_header readdir_header_break = {
      .len = uint32_t(sizeof(struct fuse_out_header)),
  };

  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, readdir_header, readdir_payload);
  SetServerResponse(FUSE_READDIR, iov_out, 2);
  
  SET_IOVEC_WITH_HEADER(iov_out, readdir_header_break);
  SetServerResponse(FUSE_READDIR, iov_out, 1);
  
  struct dirent *entry;
  entry = readdir(dir);
  EXPECT_EQ(std::string(entry->d_name), dot);
  
  entry = readdir(dir);
  EXPECT_EQ(std::string(entry->d_name), dot_dot);
  
  entry = readdir(dir);
  EXPECT_EQ(std::string(entry->d_name), test_file);

  entry = readdir(dir);
  EXPECT_TRUE((entry == NULL));

  // Clean up.
  closedir(dir);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
