load("//tools:defs.bzl", "go_binary", "go_cov")
load("//tools:deps.bzl", "deps_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "gvisor_sentry",
    srcs = ["sentry_main.go"],
    noasan = True,
    pure = True,
    visibility = ["//visibility:public"],
    x_defs = {"gvisor.dev/gvisor/runsc/version.version": "{STABLE_VERSION}"},
    deps = [
        "//runsc/cli",
        "//runsc/cmd/sentry/sentrycmd",
        "//runsc/cmd/util",
        "//runsc/gvisorbinaries",
    ],
)

go_binary(
    name = "gvisor_sentry-race",
    srcs = ["sentry_main.go"],
    gotags = ["lockdep"],
    noasan = True,
    race = "on",
    static = True,
    visibility = ["//debian:__pkg__"],
    x_defs = {"gvisor.dev/gvisor/runsc/version.version": "{STABLE_VERSION}"},
    deps = [
        "//runsc/cli",
        "//runsc/cmd/sentry/sentrycmd",
        "//runsc/cmd/util",
        "//runsc/gvisorbinaries",
    ],
)

COVERAGE_SRCS = [
    "sentry_main.go",
    "//:go.mod",
    "//:go.sum",
    "//:gopath",
    "//tools:build_cover.sh",
    "//tools:go-allow-internal.patch",
]

COVERAGE_CMD = (
    "\"$(location //tools:build_cover.sh)\" " +
    "\"$(location %s)\" " +
    "\"$(location //:gopath)\" " +
    "\"$(location //:go.mod)\" " +
    "\"$(location //:go.sum)\" " +
    "\"$(location sentry_main.go)\" " +
    "\"$(location //tools:go-allow-internal.patch)\" " +
    "\"%s\" "
)

go_cov(
    name = "gvisor_sentry_coverage",
    srcs = COVERAGE_SRCS,
    outs = ["gvisor_sentry_cov"],
    cmd = COVERAGE_CMD % ("//runsc/cmd/sentry:gvisor_sentry_cov", "false"),
    visibility = ["//debian:__pkg__"],
)

go_cov(
    name = "gvisor_sentry_race_coverage",
    srcs = COVERAGE_SRCS,
    outs = ["gvisor_sentry_race_cov"],
    cmd = COVERAGE_CMD % ("//runsc/cmd/sentry:gvisor_sentry_race_cov", "true"),
    visibility = ["//debian:__pkg__"],
)

go_binary(
    name = "gvisor_sentry_plugin_stack",
    srcs = ["sentry_main_plugin_stack.go"],
    gotags = ["network_plugins"],
    nogo = False,
    pure = False,
    static = True,
    tags = ["network_plugins"],
    visibility = ["//visibility:public"],
    x_defs = {"gvisor.dev/gvisor/runsc/version.version": "{STABLE_VERSION}"},
    deps = [
        "//pkg/sentry/socket/plugin/stack",
        "//runsc/cli",
        "//runsc/cmd/sentry/sentrycmd",
        "//runsc/cmd/util",
        "//runsc/gvisorbinaries",
    ],
)

deps_test(
    name = "gvisor_sentry_deps_test",
    # The sentry binaries contain the sentry, and nothing else.
    # Keep this tight.
    allowed = [
        "//runsc/cli",
        "//runsc/cmd/sandboxsetup",
        "//runsc/cmd/sentry/sentrycmd",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/donation",
        "//runsc/flag",
        "//runsc/gvisorbinaries",
        "//runsc/profile",
        "//runsc/starttime",
        "//runsc/version",

        # External deps.
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_google_btree//:go_default_library",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_moby_sys_capability//:go_default_library",
        "@com_github_mohae_deepcopy//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go/features:go_default_library",
        "@io_bazel_rules_go//go/tools/coverdata",
        "@org_golang_x_exp//constraints:go_default_library",
        "@org_golang_x_mod//semver:go_default_library",
        "@org_golang_x_sync//errgroup:go_default_library",
        "@org_golang_x_sys//cpu:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
        "@org_golang_x_time//rate:go_default_library",
    ],
    allowed_prefixes = [
        "@org_golang_google_protobuf//",
        "//pkg",
        "//runsc/boot",
        "//runsc/specutils",
    ],
    definitely_not_allowed_prefixes = [
        # Container-management side of runsc:
        "//runsc/container",
        "//runsc/sandbox",

        # Gofers:
        "//runsc/fsgofer",

        # Other sidecar binaries:
        "//runsc/checkpointgofer",
        "//runsc/cmd/metricserver",
        "//runsc/metricserver",
    ],
    targets = [
        ":gvisor_sentry",
        ":gvisor_sentry-race",
        ":gvisor_sentry_plugin_stack",
    ],
)
