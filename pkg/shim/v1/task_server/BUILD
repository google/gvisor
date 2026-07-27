load("//tools:defs.bzl", "go_library", "go_test", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:__subpackages__"],
    licenses = ["notice"],
)

proto_library(
    name = "task_server",
    srcs = ["task_server.proto"],
    has_services = 1,
)

go_test(
    name = "taskserver_test",
    srcs = ["server_test.go"],
    library = ":taskserver",
    deps = [
        ":task_server_go_proto",
        "//pkg/cleanup",
        "@com_github_containerd_ttrpc//:go_default_library",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_google_protobuf//testing/protocmp:go_default_library",
    ],
)

go_library(
    name = "taskserver",
    srcs = ["server.go"],
    deps = [
        ":task_server_go_proto",
        "@com_github_containerd_ttrpc//:go_default_library",
    ],
)
