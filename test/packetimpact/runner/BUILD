load("//tools:defs.bzl", "bzl_library", "go_library", "go_test")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

go_test(
    name = "packetimpact_test",
    srcs = [
        "packetimpact_test.go",
    ],
    tags = [
        # Not intended to be run directly.
        "local",
        "manual",
    ],
    deps = [":runner"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//test/packetimpact:__subpackages__"],
)

go_library(
    name = "runner",
    testonly = True,
    srcs = ["dut.go"],
    visibility = ["//test/packetimpact:__subpackages__"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/packetimpact/netdevs",
        "//test/packetimpact/testbench",
        "@com_github_docker_docker//api/types/mount:go_default_library",
    ],
)
