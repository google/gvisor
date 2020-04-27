load("//tools:defs.bzl", "pkg_tar", "py_library", "py_test")
load("//benchmarks:defs.bzl", "test_deps")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "redisbenchmark",
    srcs = ["__init__.py"],
)

py_test(
    name = "redisbenchmark_test",
    srcs = ["redisbenchmark_test.py"],
    python_version = "PY3",
    deps = test_deps + [
        ":redisbenchmark",
    ],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
    ],
)
