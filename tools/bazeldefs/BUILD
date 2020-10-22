load("//tools:defs.bzl", "bzl_library", "rbe_platform", "rbe_toolchain")

package(licenses = ["notice"])

# In bazel, no special support is required for loopback networking. This is
# just a dummy data target that does not change the test environment.
genrule(
    name = "loopback",
    outs = ["loopback.txt"],
    cmd = "touch $@",
    visibility = ["//:sandbox"],
)

# We need to define a bazel platform and toolchain to specify dockerPrivileged
# and dockerRunAsRoot options, they are required to run tests on the RBE
# cluster in Kokoro.
rbe_platform(
    name = "rbe_ubuntu1604",
    constraint_values = [
        "@bazel_tools//platforms:x86_64",
        "@bazel_tools//platforms:linux",
        "@bazel_tools//tools/cpp:clang",
        "@bazel_toolchains//constraints:xenial",
        "@bazel_toolchains//constraints/sanitizers:support_msan",
    ],
    remote_execution_properties = """
        properties: {
          name: "container-image"
          value:"docker://gcr.io/cloud-marketplace/google/rbe-ubuntu16-04@sha256:93f7e127196b9b653d39830c50f8b05d49ef6fd8739a9b5b8ab16e1df5399e50"
        }
        properties: {
          name: "dockerAddCapabilities"
          value: "SYS_ADMIN"
        }
        properties: {
          name: "dockerPrivileged"
          value: "true"
        }
    """,
)

rbe_toolchain(
    name = "cc-toolchain-clang-x86_64-default",
    exec_compatible_with = [],
    tags = [
        "manual",
    ],
    target_compatible_with = [],
    toolchain = "@bazel_toolchains//configs/ubuntu16_04_clang/10.0.0/bazel_2.0.0/cc:cc-compiler-k8",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)

# Updated versions of the above, compatible with bazel3.
rbe_platform(
    name = "rbe_ubuntu1604_bazel3",
    constraint_values = [
        "@bazel_tools//platforms:x86_64",
        "@bazel_tools//platforms:linux",
        "@bazel_tools//tools/cpp:clang",
        "@bazel_toolchains_bazel3//constraints:xenial",
        "@bazel_toolchains_bazel3//constraints/sanitizers:support_msan",
    ],
    remote_execution_properties = """
        properties: {
          name: "container-image"
          value:"docker://gcr.io/cloud-marketplace/google/rbe-ubuntu16-04@sha256:b516a2d69537cb40a7c6a7d92d0008abb29fba8725243772bdaf2c83f1be2272"
        }
        properties: {
          name: "dockerAddCapabilities"
          value: "SYS_ADMIN"
        }
        properties: {
          name: "dockerPrivileged"
          value: "true"
        }
    """,
)

rbe_toolchain(
    name = "cc-toolchain-clang-x86_64-default_bazel3",
    exec_compatible_with = [],
    tags = [
        "manual",
    ],
    target_compatible_with = [],
    toolchain = "@bazel_toolchains_bazel3//configs/ubuntu16_04_clang/11.0.0/bazel_3.1.0/cc:cc-compiler-k8",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)

bzl_library(
    name = "platforms_bzl",
    srcs = ["platforms.bzl"],
    visibility = ["//visibility:private"],
)

bzl_library(
    name = "tags_bzl",
    srcs = ["tags.bzl"],
    visibility = ["//visibility:private"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)
