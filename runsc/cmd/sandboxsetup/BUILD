load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "sandboxsetup",
    srcs = [
        "caps.go",
        "flags.go",
        "fs.go",
        "gofer_mount.go",
        "process.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/fd",
        "//pkg/log",
        "//pkg/unet",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "//runsc/starttime",
        "@com_github_moby_sys_capability//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "sandboxsetup_test",
    size = "small",
    srcs = ["gofer_mount_test.go"],
    library = ":sandboxsetup",
)
