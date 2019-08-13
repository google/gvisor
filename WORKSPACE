# Load go bazel rules and gazelle.
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "45409e6c4f748baa9e05f8f6ab6efaa05739aa064e3ab94e5a1a09849c51806a",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/rules_go/releases/download/0.18.7/rules_go-0.18.7.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/0.18.7/rules_go-0.18.7.tar.gz",
    ],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "3c681998538231a2d24d0c07ed5a7658cb72bfb5fd4bf9911157c0e9ac6a2687",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.17.0/bazel-gazelle-0.17.0.tar.gz",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_register_toolchains(
    go_version = "1.12.7",
    nogo = "@//:nogo",
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

gazelle_dependencies()

# Load bazel_toolchain to support Remote Build Execution.
# See releases at https://releases.bazel.build/bazel-toolchains.html
http_archive(
    name = "bazel_toolchains",
    sha256 = "e71eadcfcbdb47b4b740eb48b32ca4226e36aabc425d035a18dd40c2dda808c1",
    strip_prefix = "bazel-toolchains-0.28.4",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-toolchains/archive/0.28.4.tar.gz",
        "https://github.com/bazelbuild/bazel-toolchains/archive/0.28.4.tar.gz",
    ],
)

# Creates a default toolchain config for RBE.
load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")

rbe_autoconfig(name = "rbe_default")

# External repositories, in sorted order.
go_repository(
    name = "com_github_cenkalti_backoff",
    commit = "2146c9339422",
    importpath = "github.com/cenkalti/backoff",
)

go_repository(
    name = "com_github_gofrs_flock",
    commit = "886344bea079",
    importpath = "github.com/gofrs/flock",
)

go_repository(
    name = "com_github_golang_mock",
    importpath = "github.com/golang/mock",
    tag = "v1.3.1",
)

go_repository(
    name = "com_github_google_go-cmp",
    importpath = "github.com/google/go-cmp",
    tag = "v0.2.0",
)

go_repository(
    name = "com_github_google_subcommands",
    commit = "636abe8753b8",
    importpath = "github.com/google/subcommands",
)

go_repository(
    name = "com_github_google_uuid",
    commit = "dec09d789f3d",
    importpath = "github.com/google/uuid",
)

go_repository(
    name = "com_github_kr_pty",
    importpath = "github.com/kr/pty",
    tag = "v1.1.1",
)

go_repository(
    name = "com_github_opencontainers_runtime-spec",
    commit = "b2d941ef6a78",
    importpath = "github.com/opencontainers/runtime-spec",
)

go_repository(
    name = "com_github_syndtr_gocapability",
    commit = "d98352740cb2",
    importpath = "github.com/syndtr/gocapability",
)

go_repository(
    name = "com_github_vishvananda_netlink",
    commit = "adb577d4a45e",
    importpath = "github.com/vishvananda/netlink",
)

go_repository(
    name = "com_github_vishvananda_netns",
    commit = "be1fbeda1936",
    importpath = "github.com/vishvananda/netns",
)

go_repository(
    name = "org_golang_x_crypto",
    commit = "c2843e01d9a2",
    importpath = "golang.org/x/crypto",
)

go_repository(
    name = "org_golang_x_net",
    commit = "d8887717615a",
    importpath = "golang.org/x/net",
)

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    tag = "v0.3.0",
)

go_repository(
    name = "org_golang_x_tools",
    commit = "36563e24a262",
    importpath = "golang.org/x/tools",
)

go_repository(
    name = "org_golang_x_sync",
    commit = "112230192c58",
    importpath = "golang.org/x/sync",
)

go_repository(
    name = "org_golang_x_sys",
    commit = "d0b11bdaac8a",
    importpath = "golang.org/x/sys",
)

go_repository(
    name = "org_golang_x_time",
    commit = "9d24e82272b4f38b78bc8cff74fa936d31ccd8ef",
    importpath = "golang.org/x/time",
)

go_repository(
    name = "org_golang_x_tools",
    commit = "aa82965741a9fecd12b026fbb3d3c6ed3231b8f8",
    importpath = "golang.org/x/tools",
)

go_repository(
    name = "com_github_google_btree",
    importpath = "github.com/google/btree",
    tag = "v1.0.0",
)

go_repository(
    name = "com_github_golang_protobuf",
    importpath = "github.com/golang/protobuf",
    tag = "v1.3.1",
)

# System Call test dependencies.
http_archive(
    name = "com_github_gflags_gflags",
    sha256 = "34af2f15cf7367513b352bdcd2493ab14ce43692d2dcd9dfc499492966c64dcf",
    strip_prefix = "gflags-2.2.2",
    urls = [
        "https://mirror.bazel.build/github.com/gflags/gflags/archive/v2.2.2.tar.gz",
        "https://github.com/gflags/gflags/archive/v2.2.2.tar.gz",
    ],
)

http_archive(
    name = "com_google_absl",
    sha256 = "01ba1185a0e6e048e4890f39e383515195bc335f0627cdddc0c325ee68be4434",
    strip_prefix = "abseil-cpp-cd86d0d20ab167c33b23d3875db68d1d4bad3a3b",
    urls = [
        "https://mirror.bazel.build/github.com/abseil/abseil-cpp/archive/cd86d0d20ab167c33b23d3875db68d1d4bad3a3b.tar.gz",
        "https://github.com/abseil/abseil-cpp/archive/cd86d0d20ab167c33b23d3875db68d1d4bad3a3b.tar.gz",
    ],
)

http_archive(
    name = "com_google_googletest",
    sha256 = "db657310d3c5ca2d3f674e3a4b79718d1d39da70604568ee0568ba8e39065ef4",
    strip_prefix = "googletest-31200def0dec8a624c861f919e86e4444e6e6ee7",
    urls = [
        "https://mirror.bazel.build/github.com/google/googletest/archive/31200def0dec8a624c861f919e86e4444e6e6ee7.tar.gz",
        "https://github.com/google/googletest/archive/31200def0dec8a624c861f919e86e4444e6e6ee7.tar.gz",
    ],
)
