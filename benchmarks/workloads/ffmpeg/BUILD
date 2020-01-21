load("@rules_pkg//:pkg.bzl", "pkg_tar")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "ffmpeg",
    srcs = ["__init__.py"],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
    ],
)
