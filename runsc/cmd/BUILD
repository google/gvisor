load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

config_setting(
    name = "metric_server_elided",
    values = {
        "compilation_mode": "fastbuild",
    },
)

# @unused
glaze_ignore = [
    "metric_server_elided.go",
    "metric_server_embedded.go",
]

# Use either metric_server_elided.go or metric_server_embedded.go
# as metric_server.go.
genrule(
    name = "metricserver_cmd",
    srcs = select({
        ":metric_server_elided": ["metric_server_elided.go"],
        "//conditions:default": ["metric_server_embedded.go"],
    }),
    outs = ["metric_server.go"],
    cmd = "cat < $(SRCS) > $(OUTS)",
)

go_library(
    name = "cmd",
    srcs = [
        "boot.go",
        "capability.go",
        "checkpoint.go",
        "chroot.go",
        "cmd.go",
        "create.go",
        "debug.go",
        "delete.go",
        "do.go",
        "events.go",
        "exec.go",
        "fd_mapping.go",
        "gofer.go",
        "help.go",
        "install.go",
        "kill.go",
        "list.go",
        "metric_export.go",
        "metric_metadata.go",
        "metric_server.go",
        "mitigate.go",
        "mitigate_extras.go",
        "path.go",
        "pause.go",
        "platforms.go",
        "portforward.go",
        "ps.go",
        "read_control.go",
        "restore.go",
        "resume.go",
        "run.go",
        "spec.go",
        "start.go",
        "state.go",
        "statefile.go",
        "symbolize.go",
        "syscalls.go",
        "umount_unsafe.go",
        "usage.go",
        "wait.go",
        "write_control.go",
    ],
    force_add_state_pkg = True,
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cleanup",
        "//pkg/coretag",
        "//pkg/coverage",
        "//pkg/cpuid",
        "//pkg/log",
        "//pkg/metric",
        "//pkg/prometheus",
        "//pkg/ring0",
        "//pkg/sentry/control",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/platform",
        "//pkg/state/pretty",
        "//pkg/state/statefile",
        "//pkg/unet",
        "//pkg/urpc",
        "//runsc/boot",
        "//runsc/cmd/metricserver/metricservercmd",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/console",
        "//runsc/container",
        "//runsc/flag",
        "//runsc/fsgofer",
        "//runsc/fsgofer/filter",
        "//runsc/metricserver/containermetrics",
        "//runsc/mitigate",
        "//runsc/profile",
        "//runsc/specutils",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@org_golang_google_protobuf//encoding/prototext:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ] + select({
        ":metric_server_elided": [],
        "//conditions:default": [
            "//runsc/cmd/metricserver",
        ],
    }),
)

go_test(
    name = "cmd_test",
    size = "small",
    srcs = [
        "capability_test.go",
        "delete_test.go",
        "exec_test.go",
        "gofer_test.go",
        "install_test.go",
        "list_test.go",
        "mitigate_test.go",
    ],
    data = [
        "//runsc",
    ],
    library = ":cmd",
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/sentry/kernel/auth",
        "//pkg/test/testutil",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/container",
        "//runsc/mitigate",
        "//runsc/specutils",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
    ],
)
