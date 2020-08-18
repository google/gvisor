load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

# Note that the check binary must be public, since an aspect may be applied
# across lots of different rules in different repositories.
go_binary(
    name = "check",
    srcs = ["main.go"],
    visibility = ["//visibility:public"],
    deps = ["//tools/nogo"],
)
