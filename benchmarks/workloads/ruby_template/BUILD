load("//tools:defs.bzl", "pkg_tar")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
        "Gemfile",
        "Gemfile.lock",
        "config.ru",
        "index.erb",
        "main.rb",
    ],
)
