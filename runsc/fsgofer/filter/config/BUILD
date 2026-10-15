load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "config",
    srcs = [
        "config.go",
        "config_amd64.go",
        "config_arm64.go",
        "config_main.go",
        "config_precompiled.go",
    ],
    importpath = "gvisor.dev/gvisor/runsc/fsgofer/filter/config",
    visibility = [
        "//runsc/fsgofer/filter:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/seccomp",
        "//pkg/seccomp/precompiledseccomp",
        "//pkg/sync",
        "//runsc/goferfilter",
        "@org_golang_x_sync//errgroup:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "config_test",
    size = "small",
    srcs = ["config_test.go"],
    embed = [":config"],
    deps = ["//pkg/seccomp"],
)
