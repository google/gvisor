load("//tools/go_generics:defs.bzl", "go_template")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_template(
    name = "generic_fstree",
    srcs = [
        "genericfstree.go",
    ],
    types = [
        "Dentry",
    ],
)
