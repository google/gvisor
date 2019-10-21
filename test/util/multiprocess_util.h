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

#ifndef GVISOR_TEST_UTIL_MULTIPROCESS_UTIL_H_
#define GVISOR_TEST_UTIL_MULTIPROCESS_UTIL_H_

#include <unistd.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "test/util/cleanup.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

// Immutable holder for a dynamically-sized array of pointers to mutable char,
// terminated by a null pointer, as required for the argv and envp arguments to
// execve(2).
class ExecveArray {
 public:
  // Constructs an empty ExecveArray.
  ExecveArray() = default;

  // Constructs an ExecveArray by copying strings from the given range. T must
  // be a range over ranges of char.
  template <typename T>
  explicit ExecveArray(T const& strs) : ExecveArray(strs.begin(), strs.end()) {}

  // Constructs an ExecveArray by copying strings from [first, last). InputIt
  // must be an input iterator over a range over char.
  template <typename InputIt>
  ExecveArray(InputIt first, InputIt last) {
    std::vector<size_t> offsets;
    auto output_it = std::back_inserter(str_);
    for (InputIt it = first; it != last; ++it) {
      offsets.push_back(str_.size());
      auto const& s = *it;
      std::copy(s.begin(), s.end(), output_it);
      str_.push_back('\0');
    }
    ptrs_.reserve(offsets.size() + 1);
    for (auto offset : offsets) {
      ptrs_.push_back(str_.data() + offset);
    }
    ptrs_.push_back(nullptr);
  }

  // Constructs an ExecveArray by copying strings from list. This overload must
  // exist independently of the single-argument template constructor because
  // std::initializer_list does not participate in template argument deduction
  // (i.e. cannot be type-inferred in an invocation of the templated
  // constructor).
  /* implicit */ ExecveArray(std::initializer_list<absl::string_view> list)
      : ExecveArray(list.begin(), list.end()) {}

  // Disable move construction and assignment since ptrs_ points into str_.
  ExecveArray(ExecveArray&&) = delete;
  ExecveArray& operator=(ExecveArray&&) = delete;

  char* const* get() const { return ptrs_.data(); }
  size_t get_size() { return str_.size(); }

 private:
  std::vector<char> str_;
  std::vector<char*> ptrs_;
};

// Simplified version of SubProcess. Returns OK and a cleanup function to kill
// the child if it made it to execve.
//
// fn is run between fork and exec. If it needs to fail, it should exit the
// process.
//
// The child pid is returned via child, if provided.
// execve's error code is returned via execve_errno, if provided.
PosixErrorOr<Cleanup> ForkAndExec(const std::string& filename,
                                  const ExecveArray& argv,
                                  const ExecveArray& envv,
                                  const std::function<void()>& fn, pid_t* child,
                                  int* execve_errno);

inline PosixErrorOr<Cleanup> ForkAndExec(const std::string& filename,
                                         const ExecveArray& argv,
                                         const ExecveArray& envv, pid_t* child,
                                         int* execve_errno) {
  return ForkAndExec(filename, argv, envv, [] {}, child, execve_errno);
}

// Equivalent to ForkAndExec, except using dirfd and flags with execveat.
PosixErrorOr<Cleanup> ForkAndExecveat(int32_t dirfd, const std::string& pathname,
                                      const ExecveArray& argv,
                                      const ExecveArray& envv, int flags,
                                      const std::function<void()>& fn,
                                      pid_t* child, int* execve_errno);

// Calls fn in a forked subprocess and returns the exit status of the
// subprocess.
//
// fn must be async-signal-safe.
PosixErrorOr<int> InForkedProcess(const std::function<void()>& fn);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_MULTIPROCESS_UTIL_H_
