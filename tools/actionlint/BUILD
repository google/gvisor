package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

config_setting(
    name = "darwin_amd64",
    constraint_values = [
        "@platforms//cpu:x86_64",
        "@platforms//os:osx",
    ],
)

config_setting(
    name = "darwin_arm64",
    constraint_values = [
        "@platforms//cpu:aarch64",
        "@platforms//os:osx",
    ],
)

config_setting(
    name = "freebsd_386_x86_32",
    constraint_values = [
        "@platforms//cpu:x86_32",
        "@platforms//os:freebsd",
    ],
)

config_setting(
    name = "freebsd_386_i386",
    constraint_values = [
        "@platforms//cpu:i386",
        "@platforms//os:freebsd",
    ],
)

config_setting(
    name = "freebsd_amd64",
    constraint_values = [
        "@platforms//cpu:x86_64",
        "@platforms//os:freebsd",
    ],
)

config_setting(
    name = "linux_386_x86_32",
    constraint_values = [
        "@platforms//cpu:x86_32",
        "@platforms//os:linux",
    ],
)

config_setting(
    name = "linux_386_i386",
    constraint_values = [
        "@platforms//cpu:i386",
        "@platforms//os:linux",
    ],
)

config_setting(
    name = "linux_amd64",
    constraint_values = [
        "@platforms//cpu:x86_64",
        "@platforms//os:linux",
    ],
)

config_setting(
    name = "linux_arm64",
    constraint_values = [
        "@platforms//cpu:aarch64",
        "@platforms//os:linux",
    ],
)

config_setting(
    name = "linux_armv6_aarch32",
    constraint_values = [
        "@platforms//cpu:aarch32",
        "@platforms//os:linux",
    ],
)

config_setting(
    name = "linux_armv6_armv7",
    constraint_values = [
        "@platforms//cpu:armv7",
        "@platforms//os:linux",
    ],
)

config_setting(
    name = "windows_386_x86_32",
    constraint_values = [
        "@platforms//cpu:x86_32",
        "@platforms//os:windows",
    ],
)

config_setting(
    name = "windows_386_i386",
    constraint_values = [
        "@platforms//cpu:i386",
        "@platforms//os:windows",
    ],
)

config_setting(
    name = "windows_amd64",
    constraint_values = [
        "@platforms//cpu:x86_64",
        "@platforms//os:windows",
    ],
)

config_setting(
    name = "windows_arm64",
    constraint_values = [
        "@platforms//cpu:aarch64",
        "@platforms//os:windows",
    ],
)

# The upstream Linux ARM release requires ARMv6 or newer. Bazel's aarch32
# constraint does not encode that minimum; armv7 also uses the same binary.
alias(
    name = "actionlint",
    actual = select({
        ":darwin_amd64": "@actionlint_darwin_amd64//:actionlint",
        ":darwin_arm64": "@actionlint_darwin_arm64//:actionlint",
        ":freebsd_386_x86_32": "@actionlint_freebsd_386//:actionlint",
        ":freebsd_386_i386": "@actionlint_freebsd_386//:actionlint",
        ":freebsd_amd64": "@actionlint_freebsd_amd64//:actionlint",
        ":linux_386_x86_32": "@actionlint_linux_386//:actionlint",
        ":linux_386_i386": "@actionlint_linux_386//:actionlint",
        ":linux_amd64": "@actionlint_linux_amd64//:actionlint",
        ":linux_arm64": "@actionlint_linux_arm64//:actionlint",
        ":linux_armv6_aarch32": "@actionlint_linux_armv6//:actionlint",
        ":linux_armv6_armv7": "@actionlint_linux_armv6//:actionlint",
        ":windows_386_x86_32": "@actionlint_windows_386//:actionlint.exe",
        ":windows_386_i386": "@actionlint_windows_386//:actionlint.exe",
        ":windows_amd64": "@actionlint_windows_amd64//:actionlint.exe",
        ":windows_arm64": "@actionlint_windows_arm64//:actionlint.exe",
    }),
    visibility = ["//:__pkg__"],
)
