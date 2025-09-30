load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "integration_test",
    size = "large",
    srcs = [
        "exec_test.go",
        "integration_test.go",
    ],

    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    library = ":integration",
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        "local",
        "manual",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/kernel/auth",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "//runsc/specutils",
        "@com_github_docker_docker//api/types/mount:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "integration_runtime_test",
    size = "large",
    srcs = [
        "integration_runtime_test.go",
    ],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    library = ":integration",
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        "local",
        "manual",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/fsutil",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "@com_github_docker_docker//api/types/mount:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "runtime_in_docker_test",
    size = "large",
    srcs = [
        "runtime_in_docker_test.go",
    ],
    # runsc is needed to invalidate the bazel cache in case of any code changes.
    data = ["//runsc"],
    library = ":integration",
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        "local",
        "manual",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "@com_github_docker_docker//api/types/mount:go_default_library",
    ],
)

go_library(
    name = "integration",
    srcs = ["integration.go"],
)
