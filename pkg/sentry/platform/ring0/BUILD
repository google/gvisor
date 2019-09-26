load("//tools/go_stateify:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

package(licenses = ["notice"])

go_template(
    name = "defs",
    srcs = select(
    {
        "@bazel_tools//src/conditions:linux_aarch64": ["defs.go", "defs_arm64.go", "offsets_arm64.go", "aarch64.go",],
        "//conditions:default": ["defs.go", "defs_amd64.go", "offsets_amd64.go", "x86.go",],
    },
    ),
    visibility = [":__subpackages__"],
)

go_template_instance(
    name = "defs_impl",
    out = "defs_impl.go",
    package = "ring0",
    template = ":defs",
)

genrule(
    name = "entry_impl",
    srcs = ["entry_amd64.s", "entry_arm64.s"],
    outs = ["entry_impl.s"],
    cmd = select(
    {
        "@bazel_tools//src/conditions:linux_aarch64": "(echo -e '// build +arm64\\n' && $(location //pkg/sentry/platform/ring0/gen_offsets) && cat $(location entry_arm64.s)) > $@",
        "//conditions:default": "(echo -e '// build +amd64\\n' && $(location //pkg/sentry/platform/ring0/gen_offsets) && cat $(location entry_amd64.s)) > $@",
    },
    ),
    tools = ["//pkg/sentry/platform/ring0/gen_offsets"],
)

go_library(
    name = "ring0",
    srcs = [
        "defs_impl.go",
        "entry_amd64.go",
        "entry_arm64.go",
        "entry_impl.s",
        "kernel.go",
        "kernel_amd64.go",
        "kernel_arm64.go",
        "kernel_unsafe.go",
        "lib_amd64.go",
        "lib_amd64.s",
        "lib_arm64.go",
        "ring0.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/platform/ring0",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/cpuid",
        "//pkg/sentry/platform/ring0/pagetables",
        "//pkg/sentry/usermem",
    ],
)
