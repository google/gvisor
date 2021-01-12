load("//tools:defs.bzl", "go_add_tags", "go_embed_data", "go_library")

package(licenses = ["notice"])

go_embed_data(
    name = "vdso_bin",
    src = "//vdso:vdso.so",
    package = "vdsodata",
    var = "Binary",
)

[
    # Generate multiple tagged files. Note that the contents of all files
    # will be the same (i.e. vdso_arm64.go will contain the amd64 vdso), but
    # the build tags will ensure only one is selected. When we generate the
    # "Go" branch, we select all archiecture files from the relevant build.
    # This is a hack around some limitations for "out" being a configurable
    # attribute and selects for srcs. See also tools/go_branch.sh.
    go_add_tags(
        name = "vdso_%s" % arch,
        src = ":vdso_bin",
        out = "vdso_%s.go" % arch,
        go_tags = [arch],
    )
    for arch in ("amd64", "arm64")
]

go_library(
    name = "vdsodata",
    srcs = [
        "vdsodata.go",
        ":vdso_amd64",
        ":vdso_arm64",
    ],
    marshal = False,
    stateify = False,
    visibility = ["//pkg/sentry:internal"],
)
