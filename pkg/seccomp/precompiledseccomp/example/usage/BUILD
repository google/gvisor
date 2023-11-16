load("//pkg/seccomp/precompiledseccomp:defs.bzl", "precompiled_seccomp_rules")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

precompiled_seccomp_rules(
    name = "example_precompiled",
    out = "usage_embedded.go",
    out_package_name = "usage",
    programs_to_compile_go_import = "gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp/example",
    programs_to_compile_go_library = "//pkg/seccomp/precompiledseccomp/example",
)

go_library(
    name = "usage",
    srcs = [
        "usage.go",
        "usage_embedded.go",
    ],
    deps = [
        "//pkg/bpf",
        "//pkg/seccomp/precompiledseccomp",
        "//pkg/seccomp/precompiledseccomp/example",
        "//pkg/sync",
    ],
)

go_test(
    name = "usage_test",
    srcs = ["usage_test.go"],
    library = ":usage",
    deps = [
        "//pkg/bpf",
        "//pkg/seccomp",
        "//pkg/seccomp/precompiledseccomp",
        "//pkg/seccomp/precompiledseccomp/example",
    ],
)
