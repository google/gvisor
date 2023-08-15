load("//tools:defs.bzl", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# helloworld_bundler is a Go program that imports helloworld/helloworld.go and
# calls its functions. Therefore, it should print "Hello, gVisor!\n" to stdout,
# as helloworld/helloworld_bundlee.go does.
go_binary(
    name = "helloworld_bundler",
    srcs = ["helloworld_bundler.go"],
    deps = [
        "//tools/embeddedbinary/test/helloworld",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

# helloworld_test is a test that executes helloworld_bundler as a subprocess.
# It verifies that its output is "Hello, gVisor!\n".
go_test(
    name = "helloworld_test",
    srcs = ["helloworld_test.go"],
    data = [":helloworld_bundler"],
    deps = ["//pkg/test/testutil"],
)
