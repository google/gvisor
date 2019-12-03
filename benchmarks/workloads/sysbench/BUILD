load("//benchmarks:defs.bzl", "py_library", "py_test", "requirement")

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
    deps = [
        ":sysbench",
        requirement("attrs", False),
        requirement("atomicwrites", False),
        requirement("more-itertools", False),
        requirement("pathlib2", False),
        requirement("pluggy", False),
        requirement("py", False),
        requirement("pytest", True),
        requirement("six", False),
    ],
)

filegroup(
    name = "files",
    srcs = [
        "Dockerfile",
    ],
)
