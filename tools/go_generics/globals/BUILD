load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "globals",
    srcs = [
        "globals_visitor.go",
        "scope.go",
    ],
    importpath = "gvisor.dev/gvisor/tools/go_generics/globals",
    stateify = False,
    visibility = ["//tools/go_generics:__pkg__"],
)
