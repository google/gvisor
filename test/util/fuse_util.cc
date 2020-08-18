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

#include "test/util/fuse_util.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <string>

namespace gvisor {
namespace testing {

// Create response body with specified mode and nodeID.
fuse_entry_out DefaultEntryOut(mode_t mode, uint64_t node_id) {
  const int time_sec = 1595436289;
  const int time_nsec = 134150844;
  struct fuse_entry_out default_entry_out = {
      .nodeid = node_id,
      .generation = 0,
      .entry_valid = time_sec,
      .attr_valid = time_sec,
      .entry_valid_nsec = time_nsec,
      .attr_valid_nsec = time_nsec,
      .attr =
          (struct fuse_attr){
              .ino = node_id,
              .size = 512,
              .blocks = 4,
              .atime = time_sec,
              .mtime = time_sec,
              .ctime = time_sec,
              .atimensec = time_nsec,
              .mtimensec = time_nsec,
              .ctimensec = time_nsec,
              .mode = mode,
              .nlink = 2,
              .uid = 1234,
              .gid = 4321,
              .rdev = 12,
              .blksize = 4096,
          },
  };
  return default_entry_out;
};

}  // namespace testing
}  // namespace gvisor
