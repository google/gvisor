load("//tools:defs.bzl", "go_binary", "go_test")

package(licenses = ["notice"])

go_test(
    name = "safemount_test",
    size = "small",
    srcs = ["safemount_test.go"],
    data = [":safemount_runner"],
    deps = [
        "//pkg/test/testutil",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_binary(
    name = "safemount_runner",
    srcs = ["safemount_runner.go"],
    deps = [
        "//runsc/specutils",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
