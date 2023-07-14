load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "test_app",
    testonly = 1,
    srcs = [
        "fds.go",
        "main.go",
        "zombies.go",
    ],
    static = True,
    visibility = [
        "//runsc/container:__pkg__",
        "//test/syscalls/linux:__pkg__",
    ],
    deps = [
        "//pkg/test/testutil",
        "//pkg/unet",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_kr_pty//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
