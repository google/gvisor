load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "limits",
    srcs = [
        "context.go",
        "limits.go",
        "linux.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "limits_test",
    size = "small",
    srcs = [
        "limits_test.go",
    ],
    library = ":limits",
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
