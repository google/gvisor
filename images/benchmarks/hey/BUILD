load("//images:img.bzl", "executable_image")
load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "hey",
    embed = ["@com_github_rakyll_hey//:go_default_library"],
    pure = True,
    static = True,
)

executable_image(
    name = "hey",
    cmd = ["/bin/hey"],
    env = {"PATH": "/bin"},
    executables = {"/bin/hey": ":hey"},
    image_name = "benchmarks/hey",
)
