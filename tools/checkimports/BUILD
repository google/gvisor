load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "checkimports",
    srcs = ["check_imports.go"],
    importpath = "gvisor.dev/gvisor/tools/checkimports",
    nogo = False,
    visibility = ["//tools/nogo:__subpackages__"],
    deps = [
        "@org_golang_x_tools//go/analysis:go_default_library",
    ],
)

go_test(
    name = "checkimports_test",
    size = "small",
    srcs = ["check_imports_test.go"],
    embed = [":checkimports"],
    deps = [
        "@org_golang_x_tools//go/analysis:go_default_library",
    ],
)
