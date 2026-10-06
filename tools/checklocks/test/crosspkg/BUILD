load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "crosspkg",
    srcs = ["crosspkg.go"],
    importpath = "gvisor.dev/gvisor/tools/checklocks/test/crosspkg",
    # See next level up.
    marshal = False,
    stateify = False,
    visibility = ["//tools/checklocks/test:__pkg__"],
    deps = ["//tools/checklocks/test/atomic"],
)
