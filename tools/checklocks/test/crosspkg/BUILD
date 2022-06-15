load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "crosspkg",
    srcs = ["crosspkg.go"],
    # See next level up.
    marshal = False,
    stateify = False,
    visibility = ["//tools/checklocks/test:__pkg__"],
)
