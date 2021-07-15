// Copyright 2021 The gVisor Authors.
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

#ifndef GVISOR_TEST_UTIL_VERITY_UTIL_H_
#define GVISOR_TEST_UTIL_VERITY_UTIL_H_

#include <stdint.h>

#include <vector>

#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

#ifndef FS_IOC_ENABLE_VERITY
#define FS_IOC_ENABLE_VERITY 1082156677
#endif

#ifndef FS_IOC_MEASURE_VERITY
#define FS_IOC_MEASURE_VERITY 3221513862
#endif

#ifndef FS_VERITY_FL
#define FS_VERITY_FL 1048576
#endif

#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS 2148034049
#endif

struct fsverity_digest {
  unsigned short digest_algorithm;
  unsigned short digest_size; /* input/output */
  unsigned char digest[];
};

struct EnableTarget {
  std::string path;
  int flags;

  EnableTarget(std::string path, int flags) : path(path), flags(flags) {}
};

constexpr int kMaxDigestSize = 64;
constexpr int kDefaultDigestSize = 32;
constexpr char kContents[] = "foobarbaz";
constexpr char kMerklePrefix[] = ".merkle.verity.";
constexpr char kMerkleRootPrefix[] = ".merkleroot.verity.";

// Get the Merkle tree file path for |path|.
std::string MerklePath(absl::string_view path);

// Get the root Merkle tree file path for |path|.
std::string MerkleRootPath(absl::string_view path);

// Provide a function to convert bytes to hex string, since
// absl::BytesToHexString does not seem to be compatible with golang
// hex.DecodeString used in verity due to zero-padding.
std::string BytesToHexString(uint8_t bytes[], int size);

// Flip a random bit in the file represented by fd.
PosixError FlipRandomBit(int fd, int size);

// Mount a verity on the tmpfs and enable both the file and the direcotry. Then
// mount a new verity with measured root hash.
PosixErrorOr<std::string> MountVerity(std::string tmpfs_dir,
                                      std::string filename,
                                      std::vector<EnableTarget> targets);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_VERITY_UTIL_H_
