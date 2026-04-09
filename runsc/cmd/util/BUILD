load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "util",
    srcs = [
        "caps.go",
        "flags.go",
        "fs.go",
        "process.go",
        "tpu.go",
        "util.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
        "//tools:__subpackages__",
    ],
    deps = [
        "//pkg/abi/tpu",
        "//pkg/fd",
        "//pkg/log",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "//runsc/starttime",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_moby_sys_capability//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
