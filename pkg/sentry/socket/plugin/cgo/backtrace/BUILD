load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

config_setting(
    name = "plugin_tldk",
    values = {"define": "plugin_tldk=true"},
)

go_test(
    name = "backtrace_test",
    size = "small",
    srcs = [
        "backtrace_test.go",
        "backtrace_unsafe.go",
    ],
    cdeps = ["@libpluginstack//:libpluginstack"],
    cgo = True,
    # The shared Nogo transition builds ARM64 and cgo-disabled variants; this
    # test must link the actual native plugin archive.
    nogo = False,
    rundir = ".",
    static = True,
    # Exercise the existing Linux x86_64/IVB archive built for runsc-plugin-stack.
    target_compatible_with = select({
        ":plugin_tldk": [
            "@platforms//cpu:x86_64",
            "@platforms//os:linux",
        ],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
)
