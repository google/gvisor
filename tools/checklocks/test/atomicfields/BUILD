load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "atomicfields",
    srcs = ["atomicfields.go"],
    marshal = False,
    stateify = False,
    visibility = ["//tools/checklocks/test/crosspkg:__pkg__"],
    deps = ["//pkg/atomicbitops"],
)
