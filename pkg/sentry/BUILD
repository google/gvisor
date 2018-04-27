# This BUILD file defines a package_group that allows for interdependencies for
# sentry-internal packages.

package(licenses = ["notice"])  # Apache 2.0

package_group(
    name = "internal",
    packages = [
        "//pkg/sentry/...",
        "//runsc/...",
    ],
)
