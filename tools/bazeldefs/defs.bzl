"""Meta and miscellaneous rules."""

load("@bazel_skylib//rules:build_test.bzl", _build_test = "build_test")
load("@bazel_skylib//:bzl_library.bzl", _bzl_library = "bzl_library")

build_test = _build_test
bzl_library = _bzl_library
more_shards = 4
most_shards = 8
version = "//tools/bazeldefs:version"

def short_path(path):
    return path

def proto_library(name, has_services = None, **kwargs):
    native.proto_library(
        name = name,
        **kwargs
    )

def select_arch(amd64 = "amd64", arm64 = "arm64", default = None, **kwargs):
    values = {
        "@bazel_tools//src/conditions:linux_x86_64": amd64,
        "@bazel_tools//src/conditions:linux_aarch64": arm64,
    }
    if default:
        values["//conditions:default"] = default
    return select(values, **kwargs)

def select_system(linux = ["__linux__"], darwin = [], **kwargs):
    return select({
        "@bazel_tools//src/conditions:darwin": darwin,
        "//conditions:default": linux,
    })

arch_config = [
    "//command_line_option:cpu",
    "//command_line_option:crosstool_top",
    "//command_line_option:platforms",
]

def arm64_config(settings, attr):
    return {
        "//command_line_option:cpu": "aarch64",
        "//command_line_option:crosstool_top": "@crosstool//:toolchains",
        "//command_line_option:platforms": "@io_bazel_rules_go//go/toolchain:linux_arm64",
    }

def amd64_config(settings, attr):
    return {
        "//command_line_option:cpu": "k8",
        "//command_line_option:crosstool_top": "@crosstool//:toolchains",
        "//command_line_option:platforms": "@io_bazel_rules_go//go/toolchain:linux_amd64",
    }

transition_allowlist = "@bazel_tools//tools/allowlists/function_transition_allowlist"

def default_installer():
    return None

def default_net_util():
    return []  # Nothing needed.

def coreutil():
    return []  # Nothing needed.
