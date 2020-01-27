load("//tools:defs.bzl", "pkg_tar", "py_library", "py_requirement", "py_test")

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
        py_requirement("attrs", False),
        py_requirement("atomicwrites", False),
        py_requirement("more-itertools", False),
        py_requirement("pathlib2", False),
        py_requirement("pluggy", False),
        py_requirement("py", False),
        py_requirement("pytest", True),
        py_requirement("six", False),
    ],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
    ],
)
