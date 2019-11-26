load("//benchmarks:defs.bzl", "py_library", "py_test", "requirement")

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
    deps = [
        ":syscall",
        requirement("attrs", False),
        requirement("atomicwrites", False),
        requirement("more-itertools", False),
        requirement("pluggy", False),
        requirement("py", False),
        requirement("pytest", True),
    ],
)

filegroup(
    name = "files",
    srcs = [
        "Dockerfile",
        "syscall.c",
    ],
)
