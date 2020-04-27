load("//tools:defs.bzl", "pkg_tar")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
        "index.hbs",
        "index.js",
        "package.json",
        "package-lock.json",
    ],
)
