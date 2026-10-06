load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "constraintutil",
    srcs = ["constraintutil.go"],
    importpath = "gvisor.dev/gvisor/tools/constraintutil",
    marshal = False,
    stateify = False,
    visibility = ["//tools:__subpackages__"],
)

go_test(
    name = "constraintutil_test",
    size = "small",
    srcs = ["constraintutil_test.go"],
    embed = [":constraintutil"],
)
