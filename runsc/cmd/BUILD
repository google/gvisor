package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "cmd",
    srcs = [
        "boot.go",
        "capability.go",
        "checkpoint.go",
        "cmd.go",
        "create.go",
        "debug.go",
        "delete.go",
        "events.go",
        "exec.go",
        "gofer.go",
        "kill.go",
        "list.go",
        "path.go",
        "pause.go",
        "ps.go",
        "restore.go",
        "resume.go",
        "run.go",
        "start.go",
        "state.go",
        "wait.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/runsc/cmd",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/p9",
        "//pkg/sentry/control",
        "//pkg/sentry/kernel/auth",
        "//pkg/urpc",
        "//runsc/boot",
        "//runsc/container",
        "//runsc/fsgofer",
        "//runsc/specutils",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "cmd_test",
    size = "small",
    srcs = [
        "delete_test.go",
        "exec_test.go",
    ],
    embed = [":cmd"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/control",
        "//pkg/sentry/kernel/auth",
        "//pkg/urpc",
        "//runsc/boot",
        "@com_github_google_go-cmp//cmp:go_default_library",
        "@com_github_google_go-cmp//cmp/cmpopts:go_default_library",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
    ],
)
