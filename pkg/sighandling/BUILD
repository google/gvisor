load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "sighandling",
    srcs = [
        "sighandling_linux.go",
        "sighandling_linux_unsafe.go",
        "sighandling_stub.go",
        "sighandling_unix.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
