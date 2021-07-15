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

#include "test/util/verity_util.h"

#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/temp_path.h"

namespace gvisor {
namespace testing {

std::string BytesToHexString(uint8_t bytes[], int size) {
  std::stringstream ss;
  ss << std::hex;
  for (int i = 0; i < size; ++i) {
    ss << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
  }
  return ss.str();
}

std::string MerklePath(absl::string_view path) {
  return JoinPath(Dirname(path),
                  std::string(kMerklePrefix) + std::string(Basename(path)));
}

std::string MerkleRootPath(absl::string_view path) {
  return JoinPath(Dirname(path),
                  std::string(kMerkleRootPrefix) + std::string(Basename(path)));
}

PosixError FlipRandomBit(int fd, int size) {
  // Generate a random offset in the file.
  srand(time(nullptr));
  unsigned int seed = 0;
  int random_offset = rand_r(&seed) % size;

  // Read a random byte and flip a bit in it.
  char buf[1];
  RETURN_ERROR_IF_SYSCALL_FAIL(PreadFd(fd, buf, 1, random_offset));
  buf[0] ^= 1;
  RETURN_ERROR_IF_SYSCALL_FAIL(PwriteFd(fd, buf, 1, random_offset));
  return NoError();
}

PosixErrorOr<std::string> MountVerity(std::string tmpfs_dir,
                                      std::string filename,
                                      std::vector<EnableTarget> targets) {
  // Mount a verity fs on the existing tmpfs mount.
  std::string mount_opts = "lower_path=" + tmpfs_dir;
  ASSIGN_OR_RETURN_ERRNO(TempPath verity_dir, TempPath::CreateDir());
  RETURN_ERROR_IF_SYSCALL_FAIL(
      mount("", verity_dir.path().c_str(), "verity", 0, mount_opts.c_str()));

  // Enable the file, symlink(if provided) and the directory.
  ASSIGN_OR_RETURN_ERRNO(
      auto fd, Open(JoinPath(verity_dir.path(), filename), O_RDONLY, 0777));
  RETURN_ERROR_IF_SYSCALL_FAIL(ioctl(fd.get(), FS_IOC_ENABLE_VERITY));

  for (const EnableTarget& target : targets) {
    ASSIGN_OR_RETURN_ERRNO(
        auto target_fd,
        Open(JoinPath(verity_dir.path(), target.path), target.flags, 0777));
    RETURN_ERROR_IF_SYSCALL_FAIL(ioctl(target_fd.get(), FS_IOC_ENABLE_VERITY));
  }

  ASSIGN_OR_RETURN_ERRNO(auto dir_fd, Open(verity_dir.path(), O_RDONLY, 0777));
  RETURN_ERROR_IF_SYSCALL_FAIL(ioctl(dir_fd.get(), FS_IOC_ENABLE_VERITY));

  // Measure the root hash.
  uint8_t digest_array[sizeof(struct fsverity_digest) + kMaxDigestSize] = {0};
  struct fsverity_digest* digest =
      reinterpret_cast<struct fsverity_digest*>(digest_array);
  digest->digest_size = kMaxDigestSize;
  RETURN_ERROR_IF_SYSCALL_FAIL(
      ioctl(dir_fd.get(), FS_IOC_MEASURE_VERITY, digest));

  // Mount a verity fs with specified root hash.
  mount_opts +=
      ",root_hash=" + BytesToHexString(digest->digest, digest->digest_size);
  ASSIGN_OR_RETURN_ERRNO(TempPath verity_with_hash_dir, TempPath::CreateDir());
  RETURN_ERROR_IF_SYSCALL_FAIL(mount("", verity_with_hash_dir.path().c_str(),
                                     "verity", 0, mount_opts.c_str()));
  // Verity directories should not be deleted. Release the TempPath objects to
  // prevent those directories from being deleted by the destructor.
  verity_dir.release();
  return verity_with_hash_dir.release();
}

}  // namespace testing
}  // namespace gvisor
