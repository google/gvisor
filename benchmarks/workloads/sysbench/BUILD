load("//tools:defs.bzl", "pkg_tar", "py_library", "py_test")
load("//benchmarks:defs.bzl", "test_deps")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "sysbench",
    srcs = ["__init__.py"],
)

py_test(
    name = "sysbench_test",
    srcs = ["sysbench_test.py"],
    python_version = "PY3",
    deps = test_deps + [
        ":sysbench",
    ],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
    ],
)
