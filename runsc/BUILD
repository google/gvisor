package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_binary")
load("@rules_pkg//:pkg.bzl", "pkg_deb", "pkg_tar")

go_binary(
    name = "runsc",
    srcs = [
        "main.go",
        "version.go",
    ],
    pure = "on",
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"main.version": "{STABLE_VERSION}"},
    deps = [
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/platform",
        "//runsc/boot",
        "//runsc/cmd",
        "//runsc/specutils",
        "@com_github_google_subcommands//:go_default_library",
    ],
)

# The runsc-race target is a race-compatible BUILD target. This must be built
# via "bazel build --features=race //runsc:runsc-race", since the race feature
# must apply to all dependencies due a bug in gazelle file selection.  The pure
# attribute must be off because the race detector requires linking with non-Go
# components, although we still require a static binary.
#
# Note that in the future this might be convertible to a compatible target by
# using the pure and static attributes within a select function, but select is
# not currently compatible with string attributes [1].
#
# [1] https://github.com/bazelbuild/bazel/issues/1698
go_binary(
    name = "runsc-race",
    srcs = [
        "main.go",
        "version.go",
    ],
    static = "on",
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"main.version": "{STABLE_VERSION}"},
    deps = [
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/platform",
        "//runsc/boot",
        "//runsc/cmd",
        "//runsc/specutils",
        "@com_github_google_subcommands//:go_default_library",
    ],
)

pkg_tar(
    name = "runsc-bin",
    srcs = [":runsc"],
    mode = "0755",
    package_dir = "/usr/bin",
    strip_prefix = "/runsc/linux_amd64_pure_stripped",
)

pkg_tar(
    name = "debian-data",
    extension = "tar.gz",
    deps = [
        ":runsc-bin",
    ],
)

genrule(
    name = "deb-version",
    outs = ["version.txt"],
    cmd = "$(location :runsc) -version | grep 'runsc version' | sed 's/^[^0-9]*//' > $@",
    stamp = 1,
    tools = [":runsc"],
)

pkg_deb(
    name = "runsc-debian",
    architecture = "amd64",
    data = ":debian-data",
    description_file = "debian/description",
    homepage = "https://gvisor.dev/",
    maintainer = "The gVisor Authors <gvisor-dev@googlegroups.com>",
    package = "runsc",
    postinst = "debian/postinst.sh",
    tags = [
        # TODO(b/135475885): pkg_deb requires python2:
        # https://github.com/bazelbuild/bazel/issues/8443
        "manual",
    ],
    version_file = ":version.txt",
    visibility = [
        "//visibility:public",
    ],
)

sh_test(
    name = "version_test",
    size = "small",
    srcs = ["version_test.sh"],
    data = [":runsc"],
)
