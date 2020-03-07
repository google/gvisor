load("//tools:defs.bzl", "pkg_tar", "py_library", "py_test")
load("//benchmarks:defs.bzl", "test_deps")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "syscall",
    srcs = ["__init__.py"],
)

py_test(
    name = "syscall_test",
    srcs = ["syscall_test.py"],
    python_version = "PY3",
    deps = test_deps + [
        ":syscall",
    ],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
        "syscall.c",
    ],
)
