load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "fsstress_test",
    size = "large",
    srcs = [
        "fsstress_test.go",
    ],
    embed = [":fsstress"],
    # Requires docker and runsc to be configured before the test runs.
    local = True,
    tags = ["manual"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "@com_github_docker_docker//api/types/mount:go_default_library",
    ],
)

go_library(
    name = "fsstress",
    srcs = ["fsstress.go"],
)
