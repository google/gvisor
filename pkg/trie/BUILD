load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "trie",
    srcs = ["trie.go"],
    visibility = ["//:sandbox"],
)

go_test(
    name = "trie_test",
    srcs = ["trie_test.go"],
    library = ":trie",
    deps = [
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
    ],
)
