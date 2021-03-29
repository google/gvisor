load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

package(licenses = ["notice"])

[
    # These files are tagged with relevant build architectures. We can always
    # build all the input files, which will be included only in the relevant
    # architecture builds.
    go_template(
        name = "generic_walker_%s" % arch,
        srcs = [
            "walker_generic.go",
            "walker_%s.go" % arch,
        ],
        opt_types = [
            "Visitor",
        ],
        visibility = [":__pkg__"],
    )
    for arch in ("amd64", "arm64")
]

[
    # See above.
    go_template_instance(
        name = "walker_%s_%s" % (op, arch),
        out = "walker_%s_%s.go" % (op, arch),
        package = "pagetables",
        prefix = op,
        template = ":generic_walker_%s" % arch,
        types = {
            "Visitor": "%sVisitor" % op,
        },
    )
    for op in ("map", "unmap", "lookup", "empty", "check")
    for arch in ("amd64", "arm64")
]

go_library(
    name = "pagetables",
    srcs = [
        "allocator.go",
        "allocator_unsafe.go",
        "pagetables.go",
        "pagetables_aarch64.go",
        "pagetables_amd64.go",
        "pagetables_arm64.go",
        "pagetables_x86.go",
        "pcids.go",
        "pcids_aarch64.go",
        "pcids_aarch64.s",
        "pcids_x86.go",
        "walker_amd64.go",
        "walker_arm64.go",
        "walker_generic.go",
        ":walker_empty_amd64",
        ":walker_empty_arm64",
        ":walker_lookup_amd64",
        ":walker_lookup_arm64",
        ":walker_map_amd64",
        ":walker_map_arm64",
        ":walker_unmap_amd64",
        ":walker_unmap_arm64",
    ],
    visibility = [
        "//pkg/ring0:__subpackages__",
        "//pkg/sentry/platform/kvm:__subpackages__",
    ],
    deps = [
        "//pkg/hostarch",
        "//pkg/sync",
    ],
)

go_test(
    name = "pagetables_test",
    size = "small",
    srcs = [
        "pagetables_amd64_test.go",
        "pagetables_arm64_test.go",
        "pagetables_test.go",
        ":walker_check_amd64",
        ":walker_check_arm64",
    ],
    library = ":pagetables",
    deps = [
        "//pkg/hostarch",
        "//pkg/usermem",
    ],
)
