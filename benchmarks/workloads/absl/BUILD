load("//tools:defs.bzl", "pkg_tar", "py_library", "py_requirement", "py_test")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "absl",
    srcs = ["__init__.py"],
)

py_test(
    name = "absl_test",
    srcs = ["absl_test.py"],
    python_version = "PY3",
    deps = [
        ":absl",
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
