load("//benchmarks:defs.bzl", "py_library", "py_test", "requirement")

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
    deps = [
        ":ab",
        requirement("attrs", False),
        requirement("atomicwrites", False),
        requirement("more-itertools", False),
        requirement("pathlib2", False),
        requirement("pluggy", False),
        requirement("py", False),
        requirement("pytest", True),
        requirement("setuptools", False),
        requirement("six", False),
    ],
)

filegroup(
    name = "files",
    srcs = [
        "Dockerfile",
    ],
)
