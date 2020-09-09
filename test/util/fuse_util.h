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

#ifndef GVISOR_TEST_UTIL_FUSE_UTIL_H_
#define GVISOR_TEST_UTIL_FUSE_UTIL_H_

#include <linux/fuse.h>
#include <sys/uio.h>

#include <string>
#include <vector>

namespace gvisor {
namespace testing {

// The fundamental generation function with a single argument. If passed by
// std::string or std::vector<char>, it will call specialized versions as
// implemented below.
template <typename T>
std::vector<struct iovec> FuseGenerateIovecs(T &first) {
  return {(struct iovec){.iov_base = &first, .iov_len = sizeof(first)}};
}

// If an argument is of type std::string, it must be used in read-only scenario.
// Because we are setting up iovec, which contains the original address of a
// data structure, we have to drop const qualification. Usually used with
// variable-length payload data.
template <typename T = std::string>
std::vector<struct iovec> FuseGenerateIovecs(std::string &first) {
  // Pad one byte for null-terminate c-string.
  return {(struct iovec){.iov_base = const_cast<char *>(first.c_str()),
                         .iov_len = first.size() + 1}};
}

// If an argument is of type std::vector<char>, it must be used in write-only
// scenario and the size of the variable must be greater than or equal to the
// size of the expected data. Usually used with variable-length payload data.
template <typename T = std::vector<char>>
std::vector<struct iovec> FuseGenerateIovecs(std::vector<char> &first) {
  return {(struct iovec){.iov_base = first.data(), .iov_len = first.size()}};
}

// A helper function to set up an array of iovec struct for testing purpose.
// Use variadic class template to generalize different numbers and different
// types of FUSE structs.
template <typename T, typename... Types>
std::vector<struct iovec> FuseGenerateIovecs(T &first, Types &...args) {
  auto first_iovec = FuseGenerateIovecs(first);
  auto iovecs = FuseGenerateIovecs(args...);
  first_iovec.insert(std::end(first_iovec), std::begin(iovecs),
                     std::end(iovecs));
  return first_iovec;
}

// Create a fuse_attr filled with the specified mode and inode.
fuse_attr DefaultFuseAttr(mode_t mode, uint64_t inode, uint64_t size = 512);

// Return a fuse_entry_out FUSE server response body.
fuse_entry_out DefaultEntryOut(mode_t mode, uint64_t node_id,
                               uint64_t size = 512);

}  // namespace testing
}  // namespace gvisor
#endif  // GVISOR_TEST_UTIL_FUSE_UTIL_H_
