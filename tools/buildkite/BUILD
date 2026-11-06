load("@rules_python//python:py_test.bzl", "py_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

py_test(
    name = "buildkite_test",
    srcs = [
        "buildkite.py",
        "buildkite_test.py",
    ],
    imports = ["."],
)
