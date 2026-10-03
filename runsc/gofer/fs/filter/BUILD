load("//pkg/seccomp/precompiledseccomp:defs.bzl", "precompiled_seccomp_rules")
load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

precompiled_seccomp_rules(
    name = "filter_precompiled",
    out = "filter_precompiled.go",
    exclude_in_fastbuild = True,
    out_package_name = "filter",
    programs_to_compile_go_import = "gvisor.dev/gvisor/runsc/gofer/fs/filter/config",
    programs_to_compile_go_library = "//runsc/gofer/fs/filter/config",
)

go_library(
    name = "filter",
    srcs = [
        "filter.go",
        "filter_precompiled.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/seccomp/precompiledseccomp",
        "//pkg/sync",
        "//runsc/gofer/filter",
        "//runsc/gofer/fs/filter/config",
    ],
)
