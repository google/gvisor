package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_path")
load("@bazel_gazelle//:def.bzl", "gazelle")
load("@bazel_tools//tools/build_defs/pkg:pkg.bzl", "pkg_tar")

# The sandbox filegroup is used for sandbox-internal dependencies.
package_group(
    name = "sandbox",
    packages = [
        "//...",
    ],
)

# release artifacts; see cloudbuild/release.yaml.
pkg_tar(
    name = "release",
    srcs = [
        "//runsc",
        "//runsc:runsc-debian",
    ],
    mode = "0755",
)

# gopath defines a directory that is structured in a way that is compatible
# with standard Go tools. Things like godoc, editors and refactor tools should
# work as expected.
#
# The files in this tree are symlinks to the true sources.
go_path(
    name = "gopath",
    mode = "link",
    deps = [
        "//runsc",
    ],
)

# gazelle is a set of build tools.
#
# To update the WORKSPACE from go.mod, use:
#   bazel run //:gazelle -- update-repos -from_file=go.mod
gazelle(name = "gazelle")
