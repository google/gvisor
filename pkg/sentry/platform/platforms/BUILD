# The go_library rule is imported as a different name in this case,
# in order to avoid automated tooling doing the wrong thing with the
# operating-specific dependencies listed below.
load("//tools:defs.bzl", "platforms", "select_arch", "select_system", exempt_go_library = "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

exempt_go_library(
    name = "platforms",
    srcs = [
        "platforms.go",
        "platforms_amd64.go",
        "platforms_darwin.go",
    ],
    # Nothing needs to be stateified, and stateify has trouble when select is
    # used to choose deps.
    stateify = False,
    visibility = [
        "//:sandbox",
    ],
    deps = select_system(
        darwin = [],
        linux = [
            "//pkg/sentry/platform/%s" % platform
            for platform in platforms
            if "internal" not in platforms[platform] and platform != "slimvm"
        ],
    ) + select_arch(
        # SlimVM is implemented only on amd64.
        amd64 = ["//pkg/sentry/platform/slimvm"],
        default = [],
    ),
)
