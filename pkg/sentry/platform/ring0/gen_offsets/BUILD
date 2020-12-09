load("//tools:defs.bzl", "go_binary")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "defs_impl_arm64",
    out = "defs_impl_arm64.go",
    package = "main",
    template = "//pkg/sentry/platform/ring0:defs_arm64",
)

go_template_instance(
    name = "defs_impl_amd64",
    out = "defs_impl_amd64.go",
    package = "main",
    template = "//pkg/sentry/platform/ring0:defs_amd64",
)

go_binary(
    name = "gen_offsets",
    srcs = [
        "defs_impl_amd64.go",
        "defs_impl_arm64.go",
        "main.go",
    ],
    # Use the libc malloc to avoid any extra dependencies. This is required to
    # pass the sentry deps test.
    system_malloc = True,
    visibility = [
        "//pkg/sentry/platform/kvm:__pkg__",
        "//pkg/sentry/platform/ring0:__pkg__",
    ],
    deps = [
        "//pkg/cpuid",
        "//pkg/sentry/arch",
        "//pkg/sentry/platform/ring0/pagetables",
        "//pkg/usermem",
    ],
)
