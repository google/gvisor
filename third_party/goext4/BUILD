load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

exports_files(["LICENSE"])

go_library(
    name = "goext4",
    srcs = [
        "block_group_descriptor.go",
        "block_group_descriptor_list.go",
        "directory.go",
        "directory_browser.go",
        "directory_walk.go",
        "extent.go",
        "inode.go",
        "inode_reader.go",
        "superblock.go",
        "utils.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/third_party/goext4",
)
