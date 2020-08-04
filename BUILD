load("//tools:defs.bzl", "build_test", "gazelle", "go_path")
load("//website:defs.bzl", "doc")

package(licenses = ["notice"])

exports_files(["LICENSE"])

doc(
    name = "contributing",
    src = "CONTRIBUTING.md",
    category = "Project",
    permalink = "/contributing/",
    visibility = ["//website:__pkg__"],
    weight = "20",
)

doc(
    name = "security",
    src = "SECURITY.md",
    category = "Project",
    permalink = "/security/",
    visibility = ["//website:__pkg__"],
    weight = "30",
)

doc(
    name = "governance",
    src = "GOVERNANCE.md",
    category = "Project",
    permalink = "/community/governance/",
    subcategory = "Community",
    visibility = ["//website:__pkg__"],
    weight = "20",
)

doc(
    name = "code_of_conduct",
    src = "CODE_OF_CONDUCT.md",
    category = "Project",
    permalink = "/community/code_of_conduct/",
    subcategory = "Community",
    visibility = ["//website:__pkg__"],
    weight = "99",
)

# The sandbox filegroup is used for sandbox-internal dependencies.
package_group(
    name = "sandbox",
    packages = ["//..."],
)

# For targets that will not normally build internally, we ensure that they are
# least build by a static BUILD test.
build_test(
    name = "build_test",
    targets = [
        "//test/e2e:integration_test",
        "//test/image:image_test",
        "//test/root:root_test",
    ],
)

# gopath defines a directory that is structured in a way that is compatible
# with standard Go tools. Things like godoc, editors and refactor tools should
# work as expected.
#
# The files in this tree are symlinks to the true sources.
go_path(
    name = "gopath",
    mode = "link",
    deps = [
        # Main binary.
        "//runsc",
        "//shim/v1:gvisor-containerd-shim",
        "//shim/v2:containerd-shim-runsc-v1",

        # Packages that are not dependencies of //runsc.
        "//pkg/sentry/kernel/memevent",
        "//pkg/tcpip/adapters/gonet",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/muxed",
        "//pkg/tcpip/link/sharedmem",
        "//pkg/tcpip/link/sharedmem/pipe",
        "//pkg/tcpip/link/sharedmem/queue",
        "//pkg/tcpip/link/tun",
        "//pkg/tcpip/link/waitable",
        "//pkg/tcpip/sample/tun_tcp_connect",
        "//pkg/tcpip/sample/tun_tcp_echo",
        "//pkg/tcpip/transport/tcpconntrack",
    ],
)

# gazelle is a set of build tools.
#
# To update the WORKSPACE from go.mod, use:
#   bazel run //:gazelle -- update-repos -from_file=go.mod
gazelle(name = "gazelle")
