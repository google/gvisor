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

#ifndef GVISOR_TEST_UTIL_POSIX_ERROR_H_
#define GVISOR_TEST_UTIL_POSIX_ERROR_H_

#include <string>

#include "gmock/gmock.h"
#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"
#include "test/util/logging.h"

namespace gvisor {
namespace testing {

class PosixErrorIsMatcherCommonImpl;

template <typename T>
class PosixErrorOr;

class ABSL_MUST_USE_RESULT PosixError {
 public:
  PosixError() {}
  explicit PosixError(int errno_value) : errno_(errno_value) {}
  PosixError(int errno_value, std::string msg)
      : errno_(errno_value), msg_(std::move(msg)) {}

  PosixError(PosixError&& other) = default;
  PosixError& operator=(PosixError&& other) = default;
  PosixError(const PosixError&) = default;
  PosixError& operator=(const PosixError&) = default;

  bool ok() const { return errno_ == 0; }

  // Returns a reference to *this to make matchers compatible with
  // PosixErrorOr.
  const PosixError& error() const { return *this; }

  std::string error_message() const { return msg_; }

  // ToString produces a full std::string representation of this posix error
  // including the printable representation of the errno and the error message.
  std::string ToString() const;

  // Ignores any errors. This method does nothing except potentially suppress
  // complaints from any tools that are checking that errors are not dropped on
  // the floor.
  void IgnoreError() const {}

 private:
  int errno_value() const { return errno_; }
  int errno_ = 0;
  std::string msg_;

  friend class PosixErrorIsMatcherCommonImpl;

  template <typename T>
  friend class PosixErrorOr;
};

template <typename T>
class ABSL_MUST_USE_RESULT PosixErrorOr {
 public:
  PosixErrorOr(const PosixError& error);
  PosixErrorOr(const T& value);
  PosixErrorOr(T&& value);

  PosixErrorOr(PosixErrorOr&& other) = default;
  PosixErrorOr& operator=(PosixErrorOr&& other) = default;
  PosixErrorOr(const PosixErrorOr&) = default;
  PosixErrorOr& operator=(const PosixErrorOr&) = default;

  // Conversion copy/move constructor, T must be convertible from U.
  template <typename U>
  friend class PosixErrorOr;

  template <typename U>
  PosixErrorOr(PosixErrorOr<U> other);

  template <typename U>
  PosixErrorOr& operator=(PosixErrorOr<U> other);

  // Return a reference to the error or NoError().
  const PosixError error() const;

  // Returns this->error().error_message();
  const std::string error_message() const;

  // Returns this->error().ok()
  bool ok() const;

  // Returns a reference to our current value, or CHECK-fails if !this->ok().
  const T& ValueOrDie() const&;
  T& ValueOrDie() &;
  const T&& ValueOrDie() const&&;
  T&& ValueOrDie() &&;

  // Ignores any errors. This method does nothing except potentially suppress
  // complaints from any tools that are checking that errors are not dropped on
  // the floor.
  void IgnoreError() const {}

 private:
  const int errno_value() const;
  absl::variant<T, PosixError> value_;

  friend class PosixErrorIsMatcherCommonImpl;
};

template <typename T>
PosixErrorOr<T>::PosixErrorOr(const PosixError& error) : value_(error) {}

template <typename T>
PosixErrorOr<T>::PosixErrorOr(const T& value) : value_(value) {}

template <typename T>
PosixErrorOr<T>::PosixErrorOr(T&& value) : value_(std::move(value)) {}

// Conversion copy/move constructor, T must be convertible from U.
template <typename T>
template <typename U>
inline PosixErrorOr<T>::PosixErrorOr(PosixErrorOr<U> other) {
  if (absl::holds_alternative<U>(other.value_)) {
    // T is convertible from U.
    value_ = absl::get<U>(std::move(other.value_));
  } else if (absl::holds_alternative<PosixError>(other.value_)) {
    value_ = absl::get<PosixError>(std::move(other.value_));
  } else {
    TEST_CHECK_MSG(false, "PosixErrorOr does not contain PosixError or value");
  }
}

template <typename T>
template <typename U>
inline PosixErrorOr<T>& PosixErrorOr<T>::operator=(PosixErrorOr<U> other) {
  if (absl::holds_alternative<U>(other.value_)) {
    // T is convertible from U.
    value_ = absl::get<U>(std::move(other.value_));
  } else if (absl::holds_alternative<PosixError>(other.value_)) {
    value_ = absl::get<PosixError>(std::move(other.value_));
  } else {
    TEST_CHECK_MSG(false, "PosixErrorOr does not contain PosixError or value");
  }
  return *this;
}

template <typename T>
const PosixError PosixErrorOr<T>::error() const {
  if (!absl::holds_alternative<PosixError>(value_)) {
    return PosixError();
  }
  return absl::get<PosixError>(value_);
}

template <typename T>
const int PosixErrorOr<T>::errno_value() const {
  return error().errno_value();
}

template <typename T>
const std::string PosixErrorOr<T>::error_message() const {
  return error().error_message();
}

template <typename T>
bool PosixErrorOr<T>::ok() const {
  return error().ok();
}

template <typename T>
const T& PosixErrorOr<T>::ValueOrDie() const& {
  TEST_CHECK(absl::holds_alternative<T>(value_));
  return absl::get<T>(value_);
}

template <typename T>
T& PosixErrorOr<T>::ValueOrDie() & {
  TEST_CHECK(absl::holds_alternative<T>(value_));
  return absl::get<T>(value_);
}

template <typename T>
const T&& PosixErrorOr<T>::ValueOrDie() const&& {
  TEST_CHECK(absl::holds_alternative<T>(value_));
  return std::move(absl::get<T>(value_));
}

template <typename T>
T&& PosixErrorOr<T>::ValueOrDie() && {
  TEST_CHECK(absl::holds_alternative<T>(value_));
  return std::move(absl::get<T>(value_));
}

extern ::std::ostream& operator<<(::std::ostream& os, const PosixError& e);

template <typename T>
::std::ostream& operator<<(::std::ostream& os, const PosixErrorOr<T>& e) {
  os << e.error();
  return os;
}

// NoError is a PosixError that represents a successful state, i.e. No Error.
inline PosixError NoError() { return PosixError(); }

// Monomorphic implementation of matcher IsPosixErrorOk() for a given type T.
// T can be PosixError, PosixErrorOr<>, or a reference to either of them.
template <typename T>
class MonoPosixErrorIsOkMatcherImpl : public ::testing::MatcherInterface<T> {
 public:
  void DescribeTo(std::ostream* os) const override { *os << "is OK"; }
  void DescribeNegationTo(std::ostream* os) const override {
    *os << "is not OK";
  }
  bool MatchAndExplain(T actual_value,
                       ::testing::MatchResultListener*) const override {
    return actual_value.ok();
  }
};

// Implements IsPosixErrorOkMatcher() as a polymorphic matcher.
class IsPosixErrorOkMatcher {
 public:
  template <typename T>
  operator ::testing::Matcher<T>() const {  // NOLINT
    return MakeMatcher(new MonoPosixErrorIsOkMatcherImpl<T>());
  }
};

// Monomorphic implementation of a matcher for a PosixErrorOr.
template <typename PosixErrorOrType>
class IsPosixErrorOkAndHoldsMatcherImpl
    : public ::testing::MatcherInterface<PosixErrorOrType> {
 public:
  using ValueType = typename std::remove_reference<decltype(
      std::declval<PosixErrorOrType>().ValueOrDie())>::type;

  template <typename InnerMatcher>
  explicit IsPosixErrorOkAndHoldsMatcherImpl(InnerMatcher&& inner_matcher)
      : inner_matcher_(::testing::SafeMatcherCast<const ValueType&>(
            std::forward<InnerMatcher>(inner_matcher))) {}

  void DescribeTo(std::ostream* os) const override {
    *os << "is OK and has a value that ";
    inner_matcher_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "isn't OK or has a value that ";
    inner_matcher_.DescribeNegationTo(os);
  }

  bool MatchAndExplain(
      PosixErrorOrType actual_value,
      ::testing::MatchResultListener* listener) const override {
    if (!actual_value.ok()) {
      *listener << "which has error value " << actual_value.error();
      return false;
    }

    ::testing::StringMatchResultListener inner_listener;
    const bool matches = inner_matcher_.MatchAndExplain(
        actual_value.ValueOrDie(), &inner_listener);
    const std::string inner_explanation = inner_listener.str();
    if (!inner_explanation.empty()) {
      *listener << "which contains value "
                << ::testing::PrintToString(actual_value.ValueOrDie()) << ", "
                << inner_explanation;
    }
    return matches;
  }

 private:
  const ::testing::Matcher<const ValueType&> inner_matcher_;
};

// Implements IsOkAndHolds() as a polymorphic matcher.
template <typename InnerMatcher>
class IsPosixErrorOkAndHoldsMatcher {
 public:
  explicit IsPosixErrorOkAndHoldsMatcher(InnerMatcher inner_matcher)
      : inner_matcher_(std::move(inner_matcher)) {}

  // Converts this polymorphic matcher to a monomorphic one of the given type.
  // PosixErrorOrType can be either PosixErrorOr<T> or a reference to
  // PosixErrorOr<T>.
  template <typename PosixErrorOrType>
  operator ::testing::Matcher<PosixErrorOrType>() const {  // NOLINT
    return ::testing::MakeMatcher(
        new IsPosixErrorOkAndHoldsMatcherImpl<PosixErrorOrType>(
            inner_matcher_));
  }

 private:
  const InnerMatcher inner_matcher_;
};

// PosixErrorIs() is a polymorphic matcher.  This class is the common
// implementation of it shared by all types T where PosixErrorIs() can be
// used as a Matcher<T>.
class PosixErrorIsMatcherCommonImpl {
 public:
  PosixErrorIsMatcherCommonImpl(
      ::testing::Matcher<int> code_matcher,
      ::testing::Matcher<const std::string&> message_matcher)
      : code_matcher_(std::move(code_matcher)),
        message_matcher_(std::move(message_matcher)) {}

  void DescribeTo(std::ostream* os) const;

  void DescribeNegationTo(std::ostream* os) const;

  bool MatchAndExplain(const PosixError& error,
                       ::testing::MatchResultListener* result_listener) const;

 private:
  const ::testing::Matcher<int> code_matcher_;
  const ::testing::Matcher<const std::string&> message_matcher_;
};

// Monomorphic implementation of matcher PosixErrorIs() for a given type
// T.  T can be PosixError, PosixErrorOr<>, or a reference to either of them.
template <typename T>
class MonoPosixErrorIsMatcherImpl : public ::testing::MatcherInterface<T> {
 public:
  explicit MonoPosixErrorIsMatcherImpl(
      PosixErrorIsMatcherCommonImpl common_impl)
      : common_impl_(std::move(common_impl)) {}

  void DescribeTo(std::ostream* os) const override {
    common_impl_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    common_impl_.DescribeNegationTo(os);
  }

  bool MatchAndExplain(
      T actual_value,
      ::testing::MatchResultListener* result_listener) const override {
    return common_impl_.MatchAndExplain(actual_value.error(), result_listener);
  }

 private:
  PosixErrorIsMatcherCommonImpl common_impl_;
};

inline ::testing::Matcher<int> ToErrorCodeMatcher(
    const ::testing::Matcher<int>& m) {
  return m;
}

// Implements PosixErrorIs() as a polymorphic matcher.
class PosixErrorIsMatcher {
 public:
  template <typename ErrorCodeMatcher>
  PosixErrorIsMatcher(ErrorCodeMatcher&& code_matcher,
                      ::testing::Matcher<const std::string&> message_matcher)
      : common_impl_(
            ToErrorCodeMatcher(std::forward<ErrorCodeMatcher>(code_matcher)),
            std::move(message_matcher)) {}

  // Converts this polymorphic matcher to a monomorphic matcher of the
  // given type.  T can be StatusOr<>, Status, or a reference to
  // either of them.
  template <typename T>
  operator ::testing::Matcher<T>() const {  // NOLINT
    return MakeMatcher(new MonoPosixErrorIsMatcherImpl<T>(common_impl_));
  }

 private:
  const PosixErrorIsMatcherCommonImpl common_impl_;
};

// Returns a gMock matcher that matches a PosixError or PosixErrorOr<> whose
// whose error code matches code_matcher, and whose error message matches
// message_matcher.
template <typename ErrorCodeMatcher>
PosixErrorIsMatcher PosixErrorIs(
    ErrorCodeMatcher&& code_matcher,
    ::testing::Matcher<const std::string&> message_matcher) {
  return PosixErrorIsMatcher(std::forward<ErrorCodeMatcher>(code_matcher),
                             std::move(message_matcher));
}

// Returns a gMock matcher that matches a PosixErrorOr<> which is ok() and
// value matches the inner matcher.
template <typename InnerMatcher>
IsPosixErrorOkAndHoldsMatcher<typename std::decay<InnerMatcher>::type>
IsPosixErrorOkAndHolds(InnerMatcher&& inner_matcher) {
  return IsPosixErrorOkAndHoldsMatcher<typename std::decay<InnerMatcher>::type>(
      std::forward<InnerMatcher>(inner_matcher));
}

// Internal helper for concatenating macro values.
#define POSIX_ERROR_IMPL_CONCAT_INNER_(x, y) x##y
#define POSIX_ERROR_IMPL_CONCAT_(x, y) POSIX_ERROR_IMPL_CONCAT_INNER_(x, y)

#define POSIX_ERROR_IMPL_ASSIGN_OR_RETURN_(posixerroror, lhs, rexpr) \
  auto posixerroror = (rexpr);                                       \
  if (!posixerroror.ok()) {                                          \
    return (posixerroror.error());                                   \
  }                                                                  \
  lhs = std::move(posixerroror).ValueOrDie()

#define EXPECT_NO_ERRNO(expression) \
  EXPECT_THAT(expression, IsPosixErrorOkMatcher())
#define ASSERT_NO_ERRNO(expression) \
  ASSERT_THAT(expression, IsPosixErrorOkMatcher())

#define ASSIGN_OR_RETURN_ERRNO(lhs, rexpr) \
  POSIX_ERROR_IMPL_ASSIGN_OR_RETURN_(      \
      POSIX_ERROR_IMPL_CONCAT_(_status_or_value, __LINE__), lhs, rexpr)

#define RETURN_IF_ERRNO(s) \
  do {                     \
    if (!s.ok()) return s; \
  } while (false);

#define ASSERT_NO_ERRNO_AND_VALUE(expr)   \
  ({                                      \
    auto _expr_result = (expr);           \
    ASSERT_NO_ERRNO(_expr_result);        \
    std::move(_expr_result).ValueOrDie(); \
  })

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_POSIX_ERROR_H_
