# Hermetic LLVM tools, which are only available in the Bazel build.

load("@llvm//platforms:common.bzl", "SUPPORTED_EXECS")
load("@llvm//toolchain:selects.bzl", "platform_resource_dir")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

# BPF uses the downloaded compiler and its matching resource directory.
alias(
    name = "bpf_clang",
    actual = select({
        "@llvm//platforms/config:{}_{}".format(os, cpu): platform_resource_dir(os, cpu).same_package_label("bin/clang.exe" if os == "windows" else "bin/clang")
        for os, cpu in SUPPORTED_EXECS
    }),
)

alias(
    name = "clang_resource_dir",
    actual = select({
        "@llvm//platforms/config:{}_{}".format(os, cpu): platform_resource_dir(os, cpu)
        for os, cpu in SUPPORTED_EXECS
    }),
)
