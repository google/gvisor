load("@bazel_lib//lib:write_source_files.bzl", "write_source_files")
load("@bazel_skylib//rules:native_binary.bzl", "native_test")
load("@bazel_skylib//rules:write_file.bzl", "write_file")
load("@rules_license//rules:license.bzl", "license")
load("//tools:defs.bzl", "build_test", "gazelle", "go_path")
load("//tools:gazelle.bzl", "GAZELLE_PACKAGES")
load("//tools:release.bzl", "RELEASE_RUNSC", "RELEASE_SIDECARS", "release_files")
load("//tools/nogo:defs.bzl", "nogo_config")
load("//tools/yamltest:defs.bzl", "yaml_test")
load("//website:defs.bzl", "doc")

package(
    default_applicable_licenses = [":license"],
    licenses = ["notice"],
)

license(
    name = "license",
    package_name = "gvisor",
)

exports_files([
    "CODEOWNERS",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "GOVERNANCE.md",
    "MAINTAINERS.md",
    "ADOPTERS.md",
])

write_source_files(
    name = "governance-regen",
    files = {
        "CODEOWNERS": "//governance:generated/CODEOWNERS",
        "MAINTAINERS.md": "//governance:generated/MAINTAINERS.md",
    },
)

test_suite(
    name = "governance-check",
    tests = [":governance-regen_tests"],
)

release_files(
    name = "release",
    bins = [
        "//shim:containerd-shim-runsc-v1",
    ],
    runsc = RELEASE_RUNSC,
    sidecars = RELEASE_SIDECARS,
    visibility = ["//visibility:public"],
)

nogo_config(
    name = "nogo_config",
    srcs = ["nogo.yaml"],
    visibility = [
        "//visibility:public",
    ],
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
    name = "adopters",
    src = "ADOPTERS.md",
    category = "Project",
    permalink = "/users/",
    subcategory = "Community",
    visibility = ["//website:__pkg__"],
    weight = "25",
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
    schema = "//tools/nogo/config:schema.json",
)

GITHUB_WORKFLOWS = glob(
    [
        ".github/workflows/**/*.yaml",
        ".github/workflows/**/*.yml",
    ],
    allow_empty = True,
) or fail("No GitHub workflow YAML files were found")

filegroup(
    name = "github_workflows",
    srcs = GITHUB_WORKFLOWS,
)

yaml_test(
    name = "github_workflows_test",
    srcs = [":github_workflows"],
    schema = "@github_workflow_schema//file",
)

# actionlint discovers project configuration and local actions by finding .git.
# It only stats the marker; Git metadata and history are not needed.
write_file(
    name = "actionlint_project_marker",
    out = ".git",
    content = [],
)

# A real runfiles tree is needed for project/configuration discovery. On
# Windows, enable Bazel symlink support and pass --enable_runfiles.
native_test(
    name = "github_actions_test",
    src = "//tools/actionlint",
    args = [
        "-no-color",
        "-oneline",
        "-shellcheck=",
        "-pyflakes=",
    ] + ['"$(rootpath %s)"' % workflow for workflow in GITHUB_WORKFLOWS],
    # These optional configuration files may be absent.
    # buildifier: disable=constant-glob
    data = GITHUB_WORKFLOWS + [":actionlint_project_marker"] + glob(
        [
            ".github/actionlint.yaml",
            ".github/actionlint.yml",
        ],
        allow_empty = True,
    ),
)

filegroup(
    name = "buildkite_pipelines",
    srcs = glob([".buildkite/*.yaml"]),
    visibility = ["//:sandbox"],
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
        "//test/root:crictl_test",
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
    mode = "archive",
    visibility = ["//:sandbox"],
    deps = [
        # Main binaries.
        #
        # For reasons related to reproducibility of the generated
        # files, in order to ensure that :gopath produces only a
        # a single "pure" version of all files, we can only depend
        # on go_library targets here, and not go_binary. Thus the
        # binaries have been factored into a cli package, which is
        # a good practice in any case.
        "//runsc/cli/maincli",
        "//runsc/cli/sentrycli",
        "//shim/v1/cli",
        "//webhook/pkg/cli",
        "//tools/checklocks",
        "//tools/checkescape",

        # Packages that are not dependencies of the above.
        "//pkg/sentry/kernel/memevent",
        "//pkg/sentry/socket/plugin/stack",
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
        "//sandboxexec/sandbox",
        "//tools/xdp/cmd",
    ],
)

# CC toolchain targets for cross-compilation.
# Required to be explicitly specified in bazel >= 5.
toolchain(
    name = "cc_toolchain_k8",
    target_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
    toolchain = "@crosstool//:cc-compiler-k8",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)

toolchain(
    name = "cc_toolchain_aarch64",
    target_compatible_with = [
        "@platforms//os:linux",
        "@platforms//cpu:aarch64",
    ],
    toolchain = "@crosstool//:cc-compiler-aarch64",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)

# gazelle generates Go BUILD rules from sources.
#
# Packages listed in GAZELLE_PACKAGES must match gazelle's output; presubmit
# runs //:gazelle_check to enforce this. To fix them, run:
#   bazel run //:gazelle_fix
#
# gazelle:prefix gvisor.dev/gvisor
# gazelle:go_naming_convention import
# gazelle:go_naming_convention_external go_default_library
# gazelle:map_kind go_binary go_binary //tools:defs.bzl
# gazelle:map_kind go_library go_library //tools:defs.bzl
# gazelle:map_kind go_test go_test //tools:defs.bzl
#
# proto_library is a macro whose Go targets gazelle cannot see.
# gazelle:proto disable_global
# gazelle:resolve_regexp go ^gvisor\.dev/gvisor/(.+)/([^/]+)_go_proto$ //$1:${2}_go_proto
#
# These packages name a proto_library and a go_library alike, which gazelle
# rejects when loading the BUILD file.
# gazelle:exclude pkg/eventchannel
# gazelle:exclude pkg/metric
# gazelle:exclude pkg/sentry/strace
gazelle(name = "gazelle")

# Gazelle indexes go_library rules by importpath, which unmigrated BUILD files
# omit, so resolve gvisor.dev/gvisor imports by path instead (-index=none).
GAZELLE_ARGS = [
    "-index=none",
    "-r=false",
] + GAZELLE_PACKAGES

gazelle(
    name = "gazelle_check",
    args = GAZELLE_ARGS,
    mode = "diff",
)

gazelle(
    name = "gazelle_fix",
    args = GAZELLE_ARGS,
)

exports_files([
    "go.sum",
    "go.mod",
])
