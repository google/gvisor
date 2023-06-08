load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "fpu",
    srcs = [
        "fpu.go",
        "fpu_amd64.go",
        "fpu_amd64.s",
        "fpu_amd64_unsafe.go",
        "fpu_arm64.go",
        "fpu_unsafe.go",
    ],
    marshal = True,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cpuid",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/safecopy",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
