load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "lib",
    srcs = [
        "go.go",
        "java.go",
        "lib.go",
        "nodejs.go",
        "php.go",
        "python.go",
    ],
    importpath = "gvisor.dev/gvisor/test/runtimes/proctor/lib",
    visibility = ["//test:__subpackages__"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)

go_test(
    name = "lib_test",
    size = "small",
    srcs = ["lib_test.go"],
    embed = [":lib"],
    deps = ["//pkg/test/testutil"],
)
