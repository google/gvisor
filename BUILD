load("//tools:defs.bzl", "build_test", "gazelle", "go_path")
load("//tools/nogo:defs.bzl", "nogo_config")
load("//tools/yamltest:defs.bzl", "yaml_test")
load("//website:defs.bzl", "doc")

package(licenses = ["notice"])

exports_files(["LICENSE"])

nogo_config(
    name = "nogo_config",
    srcs = ["nogo.yaml"],
    visibility = ["//:sandbox"],
)

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

yaml_test(
    name = "nogo_config_test",
    srcs = glob(["nogo*.yaml"]),
    schema = "//tools/nogo:config-schema.json",
)

yaml_test(
    name = "github_workflows_test",
    srcs = glob([".github/workflows/*.yml"]),
    schema = "@github_workflow_schema//file",
)

yaml_test(
    name = "buildkite_pipelines_test",
    srcs = glob([".buildkite/*.yaml"]),
    schema = "@buildkite_pipeline_schema//file",
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
        "//test/benchmarks/base:startup_test",
        "//test/benchmarks/base:size_test",
        "//test/benchmarks/base:sysbench_test",
        "//test/benchmarks/database:redis_test",
        "//test/benchmarks/fs:bazel_test",
        "//test/benchmarks/fs:fio_test",
        "//test/benchmarks/media:ffmpeg_test",
        "//test/benchmarks/ml:tensorflow_test",
        "//test/benchmarks/network:httpd_test",
        "//test/benchmarks/network:nginx_test",
        "//test/benchmarks/network:node_test",
        "//test/benchmarks/network:ruby_test",
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
        # Main binaries.
        #
        # For reasons related to reproducibility of the generated
        # files, in order to ensure that :gopath produces only a
        # a single "pure" version of all files, we can only depend
        # on go_library targets here, and not go_binary. Thus the
        # binaries have been factored into a cli package, which is
        # a good practice in any case.
        "//runsc/cli",
        "//shim/cli",
        "//webhook/pkg/cli",

        # Packages that are not dependencies of the above.
        "//pkg/sentry/kernel/memevent",
        "//pkg/tcpip/adapters/gonet",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/ethernet",
        "//pkg/tcpip/link/muxed",
        "//pkg/tcpip/link/pipe",
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
