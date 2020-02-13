load("//tools:defs.bzl", "pkg_tar", "py_library", "py_test")
load("//benchmarks:defs.bzl", "test_deps")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "ab",
    srcs = ["__init__.py"],
)

py_test(
    name = "ab_test",
    srcs = ["ab_test.py"],
    python_version = "PY3",
    deps = test_deps + [
        ":ab",
    ],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
    ],
)
