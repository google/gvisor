load("//tools:defs.bzl", "go_binary")
load("//tools/embeddedbinary:defs.bzl", "embedded_binary_go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# helloworld_bundlee is a simple Go program that prints "Hello, gVisor!\n"
# to stdout. It is bundled by other rules.
go_binary(
    name = "helloworld_bundlee",
    srcs = ["helloworld_bundlee.go"],
)

# helloworld generates a Go source file called "helloworld.go" which embeds
# the helloworld_bundlee program.
embedded_binary_go_library(
    name = "helloworld",
    binary = ":helloworld_bundlee",
    visibility = [
        "//tools/embeddedbinary/test:__subpackages__",
    ],
)
