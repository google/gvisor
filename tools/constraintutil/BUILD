load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "constraintutil",
    srcs = ["constraintutil.go"],
    marshal = False,
    stateify = False,
    visibility = ["//tools:__subpackages__"],
)

go_test(
    name = "constraintutil_test",
    size = "small",
    srcs = ["constraintutil_test.go"],
    library = ":constraintutil",
)
