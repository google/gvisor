"""Meta and miscellaneous rules."""

load("@bazel_skylib//rules:build_test.bzl", _build_test = "build_test")
load("@bazel_skylib//:bzl_library.bzl", _bzl_library = "bzl_library")
load("@bazel_skylib//rules:common_settings.bzl", _BuildSettingInfo = "BuildSettingInfo", _bool_flag = "bool_flag")

build_test = _build_test
bzl_library = _bzl_library
bool_flag = _bool_flag
BuildSettingInfo = _BuildSettingInfo
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
    "@io_bazel_rules_go//go/config:race",
    "//command_line_option:cpu",
    "//command_line_option:crosstool_top",
    "//command_line_option:platforms",
]

def arm64_config(settings, attr):
    return {
        # Race builds are always disabled for cross-architecture generation. We
        # can't run it locally anyways, what value can this provide?
        "@io_bazel_rules_go//go/config:race": False,
        "//command_line_option:cpu": "aarch64",
        "//command_line_option:crosstool_top": "@crosstool//:toolchains",
        "//command_line_option:platforms": "@io_bazel_rules_go//go/toolchain:linux_arm64",
    }

def amd64_config(settings, attr):
    return {
        # See above.
        "@io_bazel_rules_go//go/config:race": False,
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

def bpf_program(name, src, bpf_object, visibility, hdrs):
    """Generates BPF object files from .c source code.

    Args:
      name: target name for BPF program.
      src: BPF program souce code in C.
      bpf_object: name of generated bpf object code.
      visibility: target visibility.
      hdrs: header files, but currently unsupported.
    """
    if hdrs != []:
        fail("hdrs attribute is unsupported")

    native.genrule(
        name = name,
        srcs = [src],
        visibility = visibility,
        outs = [bpf_object],
        cmd = "clang -O2 -Wall -Werror -target bpf -c $< -o $@ -I/usr/include/$$(uname -m)-linux-gnu",
    )
