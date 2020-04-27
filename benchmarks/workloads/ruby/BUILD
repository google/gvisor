load("//tools:defs.bzl", "pkg_tar")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

filegroup(
    name = "files",
    srcs = [
        "Dockerfile",
        "Gemfile",
        "Gemfile.lock",
        "config.ru",
        "index.rb",
    ],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
        "Gemfile",
        "Gemfile.lock",
        "config.ru",
        "index.rb",
    ],
)
