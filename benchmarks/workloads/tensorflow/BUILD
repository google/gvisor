load("@rules_pkg//:pkg.bzl", "pkg_tar")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "tensorflow",
    srcs = ["__init__.py"],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
    ],
)
