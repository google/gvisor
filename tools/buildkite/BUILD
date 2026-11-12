load("@rules_python//python:py_binary.bzl", "py_binary")
load("@rules_python//python:py_library.bzl", "py_library")
load("@rules_python//python:py_test.bzl", "py_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

py_library(
    name = "buildkite_lib",
    srcs = ["buildkite.py"],
    imports = ["."],
)

py_binary(
    name = "buildkite",
    srcs = ["buildkite.py"],
)

py_test(
    name = "buildkite_test",
    srcs = ["buildkite_test.py"],
    data = [":buildkite"],
    deps = [":buildkite_lib"],
)
