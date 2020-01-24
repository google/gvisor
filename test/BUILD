package(licenses = ["notice"])  # Apache 2.0

# We need to define a bazel platform and toolchain to specify dockerPrivileged
# and dockerRunAsRoot options, they are required to run tests on the RBE
# cluster in Kokoro.
alias(
    name = "rbe_ubuntu1604",
    actual = ":rbe_ubuntu1604_r346485",
)

platform(
    name = "rbe_ubuntu1604_r346485",
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

toolchain(
    name = "cc-toolchain-clang-x86_64-default",
    exec_compatible_with = [
    ],
    target_compatible_with = [
    ],
    toolchain = "@bazel_toolchains//configs/ubuntu16_04_clang/10.0.0/bazel_2.0.0/cc:cc-compiler-k8",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)
