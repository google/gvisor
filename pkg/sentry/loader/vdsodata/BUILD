load("//tools:arch.bzl", "arch_genrule")
load("//tools:defs.bzl", "go_embed_data", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_embed_data(
    name = "vdso_bin",
    src = "//vdso:vdso.so",
    package = "vdsodata",
    var = "Binary",
)

arch_genrule(
    name = "vdso_arch",
    src = ":vdso_bin",
    template = "vdso_%s.go",
)

go_library(
    name = "vdsodata",
    srcs = [
        "vdsodata.go",
        ":vdso_arch",
    ],
    marshal = False,
    stateify = False,
    visibility = ["//pkg/sentry:internal"],
)
