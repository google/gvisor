load("//tools:defs.bzl", "go_test")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

go_test(
    name = "packetimpact_test",
    srcs = ["packetimpact_test.go"],
    tags = [
        "local",
        "manual",
    ],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "@com_github_kr_pty//:go_default_library",
    ],
)
