load("@bazel_skylib//rules:common_settings.bzl", "bool_setting")
load("@rules_python//python:py_test.bzl", "py_test")
load("//tools:defs.bzl", "bzl_library", "go_cov", "gotsan_flag_values", "gotsan_values", "select_goarch")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

bool_setting(
    name = "export_go_sources",
    build_setting_default = False,
    visibility = ["//:sandbox"],
)

config_setting(
    name = "debug",
    values = {"compilation_mode": "dbg"},
    visibility = [
        "//:sandbox",
    ],
)

config_setting(
    name = "gotsan",
    flag_values = gotsan_flag_values,
    values = gotsan_values,
    visibility = [
        "//:sandbox",
    ],
)

config_setting(
    name = "lockdep",
    values = {"define": "lockdep=true"},
    visibility = [
        "//:sandbox",
    ],
)

bzl_library(
    name = "arch_bzl",
    srcs = ["arch.bzl"],
    visibility = [
        "//:sandbox",
    ],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = [
        "//:sandbox",
    ],
)

bzl_library(
    name = "deps_bzl",
    srcs = ["deps.bzl"],
    visibility = [
        "//:sandbox",
    ],
)

bzl_library(
    name = "gazelle_bzl",
    srcs = ["gazelle.bzl"],
    visibility = [
        "//:sandbox",
    ],
)

bzl_library(
    name = "release_bzl",
    srcs = ["release.bzl"],
    visibility = [
        "//:sandbox",
    ],
    deps = [":defs_bzl"],
)

exports_files([
    "benchmark-umbrella-exports.patch",
    "build_cover.sh",
    "llvm-dev-backends.patch",
    "llvm-linux-header-default.patch",
])

# Go toolchain patched to allow imports of internal packages for coverage
# builds.
go_cov(
    name = "go_cover_toolchain",
    srcs = [
        "build_go_cover_toolchain.sh",
        "go-allow-internal.patch",
        "@go_sdk//:files",
        "@go_sdk//:host_compatible_root_file",
        # Needed by make.bash.
        "@go_sdk//:lib/time/zoneinfo.zip",
    ],
    outs = ["go_cover_toolchain.tar.gz"],
    cmd = "\"$(execpath build_go_cover_toolchain.sh)\" \"$@\" " +
          "\"$(execpath go-allow-internal.patch)\" " +
          "\"$(execpath @go_sdk//:host_compatible_root_file)\" " +
          # @go_sdk is for the host's arch, so cross-compilation is not
          # supported. The script fails upon target-arch mismatch.
          select_goarch(),
    # Only needed for coverage builds.
    tags = ["manual"],
    visibility = [
        "//runsc:__pkg__",
        "//runsc/cmd/sentry:__pkg__",
    ],
)

py_test(
    name = "lint_test",
    srcs = ["lint_test.py"],
    args = ["$(rootpath :lint.sh)"],
    data = [
        "lint.sh",
        "//:.clang-format",
    ],
)
