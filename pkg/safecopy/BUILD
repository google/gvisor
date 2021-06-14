load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "safecopy",
    srcs = [
        "atomic_amd64.s",
        "atomic_arm64.s",
        "memclr_amd64.s",
        "memclr_arm64.s",
        "memcpy_amd64.s",
        "memcpy_arm64.s",
        "safecopy.go",
        "safecopy_unsafe.go",
        "sighandler_amd64.s",
        "sighandler_arm64.s",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/syserror",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "safecopy_test",
    srcs = [
        "safecopy_test.go",
    ],
    library = ":safecopy",
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
