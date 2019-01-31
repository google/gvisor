load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

go_template(
    name = "defs",
    srcs = [
        "defs.go",
        "defs_amd64.go",
        "offsets_amd64.go",
        "x86.go",
    ],
    visibility = [":__subpackages__"],
)

go_template_instance(
    name = "defs_impl",
    out = "defs_impl.go",
    package = "ring0",
    template = ":defs",
)

genrule(
    name = "entry_impl_amd64",
    srcs = ["entry_amd64.s"],
    outs = ["entry_impl_amd64.s"],
    cmd = "(echo -e '// build +amd64\\n' && $(location //pkg/sentry/platform/ring0/gen_offsets) && cat $(SRCS)) > $@",
    tools = ["//pkg/sentry/platform/ring0/gen_offsets"],
)

go_library(
    name = "ring0",
    srcs = [
        "defs_impl.go",
        "entry_amd64.go",
        "entry_impl_amd64.s",
        "kernel.go",
        "kernel_amd64.go",
        "kernel_unsafe.go",
        "lib_amd64.go",
        "lib_amd64.s",
        "ring0.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/cpuid",
        "//pkg/sentry/platform/ring0/pagetables",
        "//pkg/sentry/usermem",
    ],
)
