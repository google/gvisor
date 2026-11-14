load("//images:img.bzl", "executable_image")
load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

filegroup(
    name = "sources",
    srcs = glob(["**"]),
    visibility = ["//images:__pkg__"],
)

go_binary(
    name = "profilehelper",
    srcs = ["main.go"],
    pure = True,
    static = True,
)

executable_image(
    name = "profile_helper",
    base = "@profile_helper_ubuntu",
    executables = {"/usr/bin/profilehelper": ":profilehelper"},
    image_name = "benchmarks/profile-helper",
)
