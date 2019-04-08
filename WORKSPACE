# Load go bazel rules and gazelle.
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "31f959ecf3687f6e0bb9d01e1e7a7153367ecd82816c9c0ae149cd0e5a92bf8c",
    url = "https://github.com/bazelbuild/rules_go/releases/download/0.18.2/rules_go-0.18.2.tar.gz",
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "3c681998538231a2d24d0c07ed5a7658cb72bfb5fd4bf9911157c0e9ac6a2687",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.17.0/bazel-gazelle-0.17.0.tar.gz",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_register_toolchains(go_version = "1.12.2")

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

gazelle_dependencies()

# Load bazel_toolchain to support Remote Build Execution.
# See releases at https://releases.bazel.build/bazel-toolchains.html
http_archive(
    name = "bazel_toolchains",
    sha256 = "67335b3563d9b67dc2550b8f27cc689b64fadac491e69ce78763d9ba894cc5cc",
    strip_prefix = "bazel-toolchains-cddc376d428ada2927ad359211c3e356bd9c9fbb",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-toolchains/archive/cddc376d428ada2927ad359211c3e356bd9c9fbb.tar.gz",
        "https://github.com/bazelbuild/bazel-toolchains/archive/cddc376d428ada2927ad359211c3e356bd9c9fbb.tar.gz",
    ],
)

# External repositories, in sorted order.
go_repository(
    name = "com_github_cenkalti_backoff",
    commit = "66e726b43552c0bab0539b28e640b89fd6862115",
    importpath = "github.com/cenkalti/backoff",
)

go_repository(
    name = "com_github_gofrs_flock",
    commit = "886344bea0798d02ff3fae16a922be5f6b26cee0",
    importpath = "github.com/gofrs/flock",
)

go_repository(
    name = "com_github_golang_mock",
    commit = "600781dde9cca80734169b9e969d9054ccc57937",
    importpath = "github.com/golang/mock",
)

go_repository(
    name = "com_github_google_go-cmp",
    commit = "3af367b6b30c263d47e8895973edcca9a49cf029",
    importpath = "github.com/google/go-cmp",
)

go_repository(
    name = "com_github_google_subcommands",
    commit = "ce3d4cfc062faac7115d44e5befec8b5a08c3faa",
    importpath = "github.com/google/subcommands",
)

go_repository(
    name = "com_github_google_uuid",
    commit = "dec09d789f3dba190787f8b4454c7d3c936fed9e",
    importpath = "github.com/google/uuid",
)

go_repository(
    name = "com_github_kr_pty",
    commit = "282ce0e5322c82529687d609ee670fac7c7d917c",
    importpath = "github.com/kr/pty",
)

go_repository(
    name = "com_github_opencontainers_runtime-spec",
    commit = "b2d941ef6a780da2d9982c1fb28d77ad97f54fc7",
    importpath = "github.com/opencontainers/runtime-spec",
)

go_repository(
    name = "com_github_syndtr_gocapability",
    commit = "d98352740cb2c55f81556b63d4a1ec64c5a319c2",
    importpath = "github.com/syndtr/gocapability",
)

go_repository(
    name = "com_github_vishvananda_netlink",
    commit = "adb577d4a45e341da53c4d9196ad4222c9a23e69",
    importpath = "github.com/vishvananda/netlink",
)

go_repository(
    name = "com_github_vishvananda_netns",
    commit = "be1fbeda19366dea804f00efff2dd73a1642fdcc",
    importpath = "github.com/vishvananda/netns",
)

go_repository(
    name = "org_golang_x_net",
    commit = "b3c676e531a6dc479fa1b35ac961c13f5e2b4d2e",
    importpath = "golang.org/x/net",
)

go_repository(
    name = "org_golang_x_sys",
    commit = "0dd5e194bbf5eb84a39666eb4c98a4d007e4203a",
    importpath = "golang.org/x/sys",
)

go_repository(
    name = "com_github_google_btree",
    commit = "4030bb1f1f0c35b30ca7009e9ebd06849dd45306",
    importpath = "github.com/google/btree",
)

# System Call test dependencies.
http_archive(
    name = "com_github_gflags_gflags",
    sha256 = "6e16c8bc91b1310a44f3965e616383dbda48f83e8c1eaa2370a215057b00cabe",
    strip_prefix = "gflags-77592648e3f3be87d6c7123eb81cbad75f9aef5a",
    urls = [
        "https://mirror.bazel.build/github.com/gflags/gflags/archive/77592648e3f3be87d6c7123eb81cbad75f9aef5a.tar.gz",
        "https://github.com/gflags/gflags/archive/77592648e3f3be87d6c7123eb81cbad75f9aef5a.tar.gz",
    ],
)

http_archive(
    name = "com_google_absl",
    strip_prefix = "abseil-cpp-master",
    urls = ["https://github.com/abseil/abseil-cpp/archive/master.zip"],
)

http_archive(
    name = "com_google_glog",
    sha256 = "eaabbfc16ecfacb36960ca9c8977f40172c51e4b03234331a1f84040a77ab12c",
    strip_prefix = "glog-781096619d3dd368cfebd33889e417a168493ce7",
    urls = [
        "https://mirror.bazel.build/github.com/google/glog/archive/781096619d3dd368cfebd33889e417a168493ce7.tar.gz",
        "https://github.com/google/glog/archive/781096619d3dd368cfebd33889e417a168493ce7.tar.gz",
    ],
)

http_archive(
    name = "com_google_googletest",
    sha256 = "353ab86e35cea1cd386115279cf4b16695bbf21b897bfbf2721cf4cb5f64ade8",
    strip_prefix = "googletest-997d343dd680e541ef96ce71ee54a91daf2577a0",
    urls = [
        "https://mirror.bazel.build/github.com/google/googletest/archive/997d343dd680e541ef96ce71ee54a91daf2577a0.zip",
        "https://github.com/google/googletest/archive/997d343dd680e541ef96ce71ee54a91daf2577a0.zip",
    ],
)
