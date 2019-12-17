load("//tools/go_stateify:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

package(licenses = ["notice"])

go_template(
    name = "defs_amd64",
    srcs = [
        "defs.go",
        "defs_amd64.go",
        "offsets_amd64.go",
        "x86.go",
    ],
    visibility = [":__subpackages__"],
)

go_template(
    name = "defs_arm64",
    srcs = [
        "aarch64.go",
        "defs.go",
        "defs_arm64.go",
        "offsets_arm64.go",
    ],
    visibility = [":__subpackages__"],
)

go_template_instance(
    name = "defs_impl_amd64",
    out = "defs_impl_amd64.go",
    package = "ring0",
    template = ":defs_amd64",
)

go_template_instance(
    name = "defs_impl_arm64",
    out = "defs_impl_arm64.go",
    package = "ring0",
    template = ":defs_arm64",
)

genrule(
    name = "entry_impl_amd64",
    srcs = ["entry_amd64.s"],
    outs = ["entry_impl_amd64.s"],
    cmd = "(echo -e '// build +amd64\\n' && $(location //pkg/sentry/platform/ring0/gen_offsets) && cat $(SRCS)) > $@",
    tools = ["//pkg/sentry/platform/ring0/gen_offsets"],
)

genrule(
    name = "entry_impl_arm64",
    srcs = ["entry_arm64.s"],
    outs = ["entry_impl_arm64.s"],
    cmd = "(echo -e '// build +arm64\\n' && $(location //pkg/sentry/platform/ring0/gen_offsets) && cat $(SRCS)) > $@",
    tools = ["//pkg/sentry/platform/ring0/gen_offsets"],
)

go_library(
    name = "ring0",
    srcs = [
        "defs_impl_amd64.go",
        "defs_impl_arm64.go",
        "entry_amd64.go",
        "entry_arm64.go",
        "entry_impl_amd64.s",
        "entry_impl_arm64.s",
        "kernel.go",
        "kernel_amd64.go",
        "kernel_arm64.go",
        "kernel_unsafe.go",
        "lib_amd64.go",
        "lib_amd64.s",
        "lib_arm64.go",
        "lib_arm64.s",
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
