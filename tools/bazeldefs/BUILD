load("//tools:defs.bzl", "rbe_platform", "rbe_toolchain")

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
    name = "rbe_ubuntu1804",
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
          value:"docker://gcr.io/cloud-marketplace/google/rbe-ubuntu18-04@sha256:713beaae338cc3f81db4b266d0d924365344b92873b37769b41f8a2d6d36a613"
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
