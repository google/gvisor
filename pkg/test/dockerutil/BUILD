load("@bazel_lib//lib:copy_file.bzl", "copy_file")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# go:embed can only match files in this package or a subdirectory.
copy_file(
    name = "run_sniffer_bin",
    src = "//tools/ioctl_sniffer:run_sniffer",
    out = "run_sniffer_copy",
    allow_symlink = True,
)

go_library(
    name = "dockerutil",
    testonly = 1,
    srcs = [
        "container.go",
        "dockerutil.go",
        "exec.go",
        "gpu.go",
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
    name = "exec_test",
    size = "small",
    srcs = ["exec_test.go"],
    embed = [":dockerutil"],
    deps = ["@com_github_docker_docker//client:go_default_library"],
)

go_test(
    name = "profile_test",
    size = "large",
    srcs = [
        "profile_test.go",
    ],
    embed = [":dockerutil"],
    # Requires docker and runsc to be configured before test runs.
    # Also requires the test to be run as root.
    local = True,
    nogo = False,
    tags = ["manual"],
    visibility = ["//:sandbox"],
)
