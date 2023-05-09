load("//tools:arch.bzl", "arch_genrule")
load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

arch_genrule(
    name = "vdso_arch",
    src = "//vdso",
    template = "vdso_%s.so",
)

go_library(
    name = "vdsodata",
    srcs = [
        "vdsodata.go",
        "vdsodata_amd64.go",
        "vdsodata_arm64.go",
    ],
    embedsrcs = [
        ":vdso_arch",  # keep
    ],
    marshal = False,
    stateify = False,
    visibility = ["//pkg/sentry:internal"],
)
