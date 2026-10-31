load("@bazel_skylib//rules:common_settings.bzl", "bool_setting")
load("@rules_python//python:py_test.bzl", "py_test")
load("//tools:defs.bzl", "bzl_library", "gotsan_flag_values", "gotsan_values")

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
)

exports_files([
    "benchmark-umbrella-exports.patch",
    "build_cover.sh",
    "go-allow-internal.patch",
    "llvm-linux-header-default.patch",
])

py_test(
    name = "lint_test",
    srcs = ["lint_test.py"],
    args = ["$(rootpath :lint.sh)"],
    data = [
        "lint.sh",
        "//:.clang-format",
    ],
)
