load("//tools:defs.bzl", "bzl_library", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "precompiledseccomp",
    srcs = ["precompiledseccomp.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/bpf",
        "//pkg/log",
        "//pkg/seccomp",
    ],
)

# @unused
glaze_ignore = [
    "precompiled_lib.tmpl.go",
    "precompile_gen.go",
]

exports_files(
    srcs = [
        "precompile_gen.go",
        "precompiled_lib.tmpl.go",
    ],
    visibility = [
        "//:sandbox",
    ],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = [
        "//:sandbox",
    ],
)

go_test(
    name = "precompiledseccomp_test",
    srcs = ["precompiledseccomp_test.go"],
    library = ":precompiledseccomp",
    deps = [
        "//pkg/abi/linux",
        "//pkg/seccomp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
