load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "dockerutil",
    testonly = 1,
    srcs = [
        "container.go",
        "dockerutil.go",
        "exec.go",
        "network.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/testutil",
        "@com_github_docker_docker//api/types:go_default_library",
        "@com_github_docker_docker//api/types/container:go_default_library",
        "@com_github_docker_docker//api/types/mount:go_default_library",
        "@com_github_docker_docker//api/types/network:go_default_library",
        "@com_github_docker_docker//client:go_default_library",
        "@com_github_docker_docker//pkg/stdcopy:go_default_library",
        "@com_github_docker_go_connections//nat:go_default_library",
    ],
)
