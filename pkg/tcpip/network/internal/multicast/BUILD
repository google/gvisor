load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "multicast",
    srcs = [
        "route_table.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "multicast_test",
    size = "small",
    srcs = ["route_table_test.go"],
    library = ":multicast",
    deps = [
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
    ],
)

go_test(
    name = "multicast_x_test",
    size = "small",
    srcs = ["example_test.go"],
    deps = [
        ":multicast",
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
    ],
)
