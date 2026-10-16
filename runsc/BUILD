load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("//tools:defs.bzl", "go_binary", "go_cov")
load("//tools:deps.bzl", "deps_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "runsc",
    srcs = ["main.go"],
    noasan = True,
    pure = True,
    tags = ["staging"],
    # Do NOT add new visibility entries here.
    # Users should depend on the gVisor release fileset,
    # not on this target directly.
    visibility = ["//:__subpackages__"],
    x_defs = {"gvisor.dev/gvisor/runsc/version.version": "{STABLE_VERSION}"},
    deps = [
        "//runsc/cli/maincli",
        "//runsc/version",
    ],
)

go_binary(
    name = "runsc-plugin-stack",
    srcs = ["main_plugin_stack.go"],
    gotags = ["network_plugins"],
    nogo = False,
    pure = False,
    static = True,
    tags = ["network_plugins"],
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"gvisor.dev/gvisor/runsc/version.version": "{STABLE_VERSION}"},
    deps = [
        "//pkg/sentry/socket/plugin/cgo",
        "//runsc/cli/maincli",
        "//runsc/sandbox",
        "//runsc/version",
    ],
)

# The runsc-race target is a race-compatible BUILD target. This must be built
# via: bazel build --features=race :runsc-race
#
# This is necessary because the race feature must apply to all dependencies
# due a bug in gazelle file selection.  The pure attribute must be off because
# the race detector requires linking with non-Go components, although we still
# require a static binary.
#
# Note that in the future this might be convertible to a compatible target by
# using the pure and static attributes within a select function, but select is
# not currently compatible with string attributes [1].
#
# [1] https://github.com/bazelbuild/bazel/issues/1698
go_binary(
    name = "runsc-race",
    srcs = ["main.go"],
    gotags = ["lockdep"],
    race = "on",
    static = True,
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"gvisor.dev/gvisor/runsc/version.version": "{STABLE_VERSION}"},
    deps = [
        "//runsc/cli/maincli",
        "//runsc/version",
    ],
)

deps_test(
    name = "runsc_deps_test",
    allowed = [
        # Sentry packages that runsc also uses. Keep them small.
        "//pkg/sentry/checkpoint",
        "//pkg/sentry/devices/nvproxy/nvconf",
        "//pkg/sentry/fscheckpoint",
        "//pkg/sentry/fscheckpoint:fscheckpoint_proto_go_proto",
        "//pkg/sentry/hostmm",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/limits",
        "//pkg/sentry/platform/platformdesc",
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sentry/seccheck/sinks/null",
        "//pkg/sentry/seccheck/sinks/remote",
        "//pkg/sentry/seccheck/sinks/remote/wire",
        "//pkg/sentry/state/checkpointfiles",
        "//pkg/sentry/usage",

        # Types that runsc and the Sentry exchange.
        "//pkg/sentry/control/controlapi",
        "//runsc/boot/sentryapi",
        "//runsc/boot/procfs",

        # Coverage support, linked through //pkg/coverage.
        "@io_bazel_rules_go//go/tools/coverdata",
    ],
    allowed_prefixes = [
        "@com_github_cenkalti_backoff//",
        "@com_github_cilium_ebpf//",
        "@com_github_coreos_go_systemd_v22//",
        "@com_github_creack_pty//",
        "@com_github_godbus_dbus_v5//",
        "@com_github_gofrs_flock//",
        "@com_github_google_subcommands//",
        "@com_github_moby_sys_capability//",
        "@com_github_mohae_deepcopy//",
        "@com_github_opencontainers_runtime_spec//",
        "@com_github_vishvananda_netlink//",
        "@com_github_vishvananda_netns//",
        "@in_gopkg_yaml_v2//",
        "@org_golang_google_protobuf//",
        "@org_golang_x_exp//",
        "@org_golang_x_mod//",
        "@org_golang_x_sync//",
        "@org_golang_x_sys//",
        "@org_golang_x_time//",
        "//",
    ],
    denied_prefixes = [
        # The Sentry and its network stack.
        "//pkg/ring0",
        "//pkg/sentry",
        "//pkg/sigframe",
        "//pkg/tcpip/link",
        "//pkg/tcpip/network",
        "//pkg/tcpip/nftables",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport",
        "//runsc/boot",
        "//runsc/cmd/sentry/sentrycmd",

        # xdp_loader, which links the network stack.
        "//tools/xdp/cmd",
    ],
    targets = [
        ":runsc",
        ":runsc-race",
    ],
)

sh_test(
    name = "version_test",
    size = "small",
    srcs = ["version_test.sh"],
    args = ["$(location :runsc)"],
    data = [":runsc"],
)

go_cov(
    name = "runsc_coverage",
    srcs = [
        "main.go",
        "//:go.mod",
        "//:go.sum",
        "//:gopath",
        "//tools:build_cover.sh",
        "//tools:go-allow-internal.patch",
    ],
    outs = ["runsc_cov"],
    cmd =
        "\"$(location //tools:build_cover.sh)\" " +
        "\"$(location //runsc:runsc_cov)\" " +
        "\"$(location //:gopath)\" " +
        "\"$(location //:go.mod)\" " +
        "\"$(location //:go.sum)\" " +
        "\"$(location main.go)\" " +
        "\"$(location //tools:go-allow-internal.patch)\" " +
        "\"false\" ",
    visibility = ["//debian:__pkg__"],
)

go_cov(
    name = "runsc_race_coverage",
    srcs = [
        "main.go",
        "//:go.mod",
        "//:go.sum",
        "//:gopath",
        "//tools:build_cover.sh",
        "//tools:go-allow-internal.patch",
    ],
    outs = ["runsc_race_cov"],
    cmd =
        "\"$(location //tools:build_cover.sh)\" " +
        "\"$(location //runsc:runsc_race_cov)\" " +
        "\"$(location //:gopath)\" " +
        "\"$(location //:go.mod)\" " +
        "\"$(location //:go.sum)\" " +
        "\"$(location main.go)\" " +
        "\"$(location //tools:go-allow-internal.patch)\" " +
        "\"true\" ",
    visibility = ["//debian:__pkg__"],
)
