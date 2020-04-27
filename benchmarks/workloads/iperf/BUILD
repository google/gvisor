load("//tools:defs.bzl", "pkg_tar", "py_library", "py_test")
load("//benchmarks:defs.bzl", "test_deps")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "iperf",
    srcs = ["__init__.py"],
)

py_test(
    name = "iperf_test",
    srcs = ["iperf_test.py"],
    python_version = "PY3",
    deps = test_deps + [
        ":iperf",
    ],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
    ],
)
