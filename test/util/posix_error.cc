// Copyright 2018 Google LLC
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

#include "test/util/posix_error.h"

#include <cassert>
#include <cerrno>
#include <cstring>
#include <string>

#include "absl/strings/str_cat.h"

namespace gvisor {
namespace testing {

std::string PosixError::ToString() const {
  if (ok()) {
    return "No Error";
  }

  std::string ret;

  char strerrno_buf[1024] = {};
  char* msg = nullptr;
  if ((msg = strerror_r(errno_, strerrno_buf, sizeof(strerrno_buf))) ==
      nullptr) {
    ret = absl::StrCat("PosixError(errno=", errno_, " strerror_r FAILED)");
  } else {
    ret = absl::StrCat("PosixError(errno=", errno_, " ", msg, ")");
  }

  if (!msg_.empty()) {
    ret.append(" ");
    ret.append(msg_);
  }

  return ret;
}

::std::ostream& operator<<(::std::ostream& os, const PosixError& e) {
  os << e.ToString();
  return os;
}

void PosixErrorIsMatcherCommonImpl::DescribeTo(std::ostream* os) const {
  *os << "has an errno value that ";
  code_matcher_.DescribeTo(os);
  *os << ", and has an error message that ";
  message_matcher_.DescribeTo(os);
}

void PosixErrorIsMatcherCommonImpl::DescribeNegationTo(std::ostream* os) const {
  *os << "has an errno value that ";
  code_matcher_.DescribeNegationTo(os);
  *os << ", or has an error message that ";
  message_matcher_.DescribeNegationTo(os);
}

bool PosixErrorIsMatcherCommonImpl::MatchAndExplain(
    const PosixError& error,
    ::testing::MatchResultListener* result_listener) const {
  ::testing::StringMatchResultListener inner_listener;

  inner_listener.Clear();
  if (!code_matcher_.MatchAndExplain(error.errno_value(), &inner_listener)) {
    *result_listener << (inner_listener.str().empty()
                             ? "whose errno value is wrong"
                             : "which has a errno value " +
                                   inner_listener.str());
    return false;
  }

  if (!message_matcher_.Matches(error.error_message())) {
    *result_listener << "whose error message is wrong";
    return false;
  }

  return true;
}

}  // namespace testing
}  // namespace gvisor
