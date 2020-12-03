"""Meta and miscellaneous rules."""

load("@bazel_skylib//rules:build_test.bzl", _build_test = "build_test")
load("@bazel_skylib//:bzl_library.bzl", _bzl_library = "bzl_library")

build_test = _build_test
bzl_library = _bzl_library
rbe_platform = native.platform
rbe_toolchain = native.toolchain
more_shards = 4
most_shards = 8

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

def select_system(linux = ["__linux__"], **kwargs):
    return linux  # Only Linux supported.

def default_installer():
    return None

def default_net_util():
    return []  # Nothing needed.

def coreutil():
    return []  # Nothing needed.
