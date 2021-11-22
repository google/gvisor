load("//tools:defs.bzl", "go_library", "select_system")

package(licenses = ["notice"])

# Don't rewrite the deps attribute of :platforms.
# @unused
glaze_ignore = [
    "platforms.go",
    "platforms_darwin.go",
]

go_library(
    name = "platforms",
    srcs = [
        "platforms.go",
        "platforms_darwin.go",
    ],
    # Nothing needs to be stateified, and stateify has trouble when select is
    # used to choose deps.
    stateify = False,
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = select_system(
        darwin = [],
        linux = [
            "//pkg/sentry/platform/kvm",
            "//pkg/sentry/platform/ptrace",
            "//runsc/boot/platforms/nonstandard",
        ],
    ),
)
