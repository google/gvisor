load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# We copy the `run_sniffer` binary here because `go:embed` can only embed
# from the current directory or subdirectories, not parents of it.
genrule(
    name = "run_sniffer_bin",
    srcs = [
        "//tools/ioctl_sniffer:run_sniffer",
    ],
    outs = ["run_sniffer_copy"],
    cmd = "cat < $(SRCS) > $@",
)

go_library(
    name = "dockerutil",
    testonly = 1,
    srcs = [
        "container.go",
        "dockerutil.go",
        "exec.go",
        "gpu.go",
        "network.go",
        "profile.go",
    ],
    embedsrcs = [
        ":run_sniffer_bin",  # keep
    ],
    nogo = False,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sync",
        "//pkg/test/testutil",
        "//runsc/cgroup",
        "@com_github_docker_docker//api/types:go_default_library",
        "@com_github_docker_docker//api/types/checkpoint:go_default_library",
        "@com_github_docker_docker//api/types/container:go_default_library",
        "@com_github_docker_docker//api/types/mount:go_default_library",
        "@com_github_docker_docker//api/types/network:go_default_library",
        "@com_github_docker_docker//client:go_default_library",
        "@com_github_docker_docker//pkg/stdcopy:go_default_library",
        "@com_github_docker_go_connections//nat:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "profile_test",
    size = "large",
    srcs = [
        "profile_test.go",
    ],
    library = ":dockerutil",
    nogo = False,
    tags = [
        # Requires docker and runsc to be configured before test runs.
        # Also requires the test to be run as root.
        "local",
        "manual",
    ],
    visibility = ["//:sandbox"],
)
