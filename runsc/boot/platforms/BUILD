# The go_library rule is imported as a different name in this case,
# in order to avoid automated tooling doing the wrong thing with the
# operating-specific dependencies listed below.
load("//tools:defs.bzl", "platforms", "select_system", exempt_go_library = "go_library")

package(licenses = ["notice"])

exempt_go_library(
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
            "//pkg/sentry/platform/%s" % platform
            for platform in platforms
            if "internal" not in platforms[platform]
        ],
    ),
)
