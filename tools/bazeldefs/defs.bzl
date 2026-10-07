"""Meta and miscellaneous rules."""

load("@bazel_skylib//:bzl_library.bzl", _bzl_library = "bzl_library")
load("@bazel_skylib//rules:build_test.bzl", _build_test = "build_test")
load("@bazel_skylib//rules:common_settings.bzl", _BuildSettingInfo = "BuildSettingInfo", _bool_flag = "bool_flag")
load("@bazel_skylib//rules:expand_template.bzl", _expand_template = "expand_template")
load("@com_google_protobuf//bazel:proto_library.bzl", _proto_library = "proto_library")

build_test = _build_test
bzl_library = _bzl_library
bool_flag = _bool_flag
BuildSettingInfo = _BuildSettingInfo
expand_template = _expand_template
more_shards = 4
most_shards = 8
version = "//tools/bazeldefs:version"

def short_path(path):
    return path

def proto_library(name, has_services = None, **kwargs):  # buildifier: disable=unused-variable
    _proto_library(
        name = name,
        **kwargs
    )

def select_arch(amd64 = None, arm64 = None, riscv64 = None, default = None, **kwargs):
    """Select an option against standard architectures.

    Args:
      amd64: the option if the architecture is amd64.
      arm64: the option if the architecture is arm64.
      riscv64: the option if the architecture is riscv64.
      default: the option if no matching architecture is provided.
      **kwargs: extra select arguments.

    Returns:
      An appropriate select."""
    values = dict()
    if amd64 != None:
        values["//tools/bazeldefs:amd64"] = amd64
    if arm64 != None:
        values["//tools/bazeldefs:arm64"] = arm64
    if riscv64 != None:
        values["//tools/bazeldefs:riscv64"] = riscv64
    if default != None:
        values["//conditions:default"] = default
    return select(values, **kwargs)

def select_system(linux = ["__linux__"], darwin = [], **_kwargs):
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

def arm64_config(_settings, _attr):
    return {
        # Disable the inherited race setting for cross-architecture generation.
        # Targets with an explicit race attribute still use instrumentation.
        "@io_bazel_rules_go//go/config:race": False,
        "//command_line_option:cpu": "aarch64",
        "//command_line_option:crosstool_top": "@crosstool//:toolchains",
        # Permit targets that explicitly enable race instrumentation to use cgo.
        # Ordinary targets still inherit the pure build setting from .bazelrc.
        "//command_line_option:platforms": "//tools/bazeldefs:linux_arm64",
    }

def amd64_config(_settings, _attr):
    return {
        # See above.
        "@io_bazel_rules_go//go/config:race": False,
        "//command_line_option:cpu": "k8",
        "//command_line_option:crosstool_top": "@crosstool//:toolchains",
        # See above.
        "//command_line_option:platforms": "//tools/bazeldefs:linux_amd64",
    }

transition_allowlist = "@bazel_tools//tools/allowlists/function_transition_allowlist"

def default_installer():
    return None

def default_net_util():
    return []  # Nothing needed.

def coreutil():
    return []  # Nothing needed.

def target_emulator():
    """Returns the user-mode emulator that runs target binaries at build time.

    The emulators are pinned, statically-linked QEMU builds for the execution
    platform's architecture (see target_emulators).

    Returns:
      A struct with:
        tools: labels to add to the tools of a genrule.
        cmd: the emulator command to run target binaries with when the
          execution platform's architecture differs from the target's, or an
          empty string if there is none. This may reference `tools` using make
          variables.
    """
    return struct(
        tools = select_arch(
            amd64 = ["//tools/bazeldefs:qemu_x86_64"],
            arm64 = ["//tools/bazeldefs:qemu_aarch64"],
            riscv64 = ["//tools/bazeldefs:qemu_riscv64"],
            default = [],
        ),
        cmd = select_arch(
            amd64 = "$(execpath //tools/bazeldefs:qemu_x86_64)",
            arm64 = "$(execpath //tools/bazeldefs:qemu_aarch64)",
            riscv64 = "$(execpath //tools/bazeldefs:qemu_riscv64)",
            default = "",
        ),
    )

def target_emulators(name):
    """Defines the user-mode emulators used by target_emulator.

    Each emulator is the pinned QEMU build for the execution platform's
    architecture (see extensions/deb_data.bzl), or a stub that fails if there
    is none. This must only be called from tools/bazeldefs/BUILD.

    Args:
      name: prefix of the emulator targets, which are named <name>_<arch>.
    """
    native.alias(
        name = name + "_aarch64",
        actual = select({
            ":amd64": "@qemu_user_amd64_files//:usr/bin/qemu-aarch64",
            "//conditions:default": ":no_emulator.sh",
        }),
        tags = ["manual"],
    )
    native.alias(
        name = name + "_riscv64",
        actual = select({
            ":amd64": "@qemu_user_amd64_files//:usr/bin/qemu-riscv64",
            ":arm64": "@qemu_user_arm64_files//:usr/bin/qemu-riscv64",
            "//conditions:default": ":no_emulator.sh",
        }),
        tags = ["manual"],
    )
    native.alias(
        name = name + "_x86_64",
        actual = select({
            ":arm64": "@qemu_user_arm64_files//:usr/bin/qemu-x86_64",
            "//conditions:default": ":no_emulator.sh",
        }),
        tags = ["manual"],
    )

def bpf_program(name, src, bpf_object, visibility, hdrs):
    """Generates BPF object files from .c source code.

    Args:
      name: target name for BPF program.
      src: BPF program source code in C.
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
