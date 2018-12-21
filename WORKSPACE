# Load go bazel rules and gazelle.
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
http_archive(
    name = "io_bazel_rules_go",
    url = "https://github.com/bazelbuild/rules_go/releases/download/0.16.5/rules_go-0.16.5.tar.gz",
    sha256 = "7be7dc01f1e0afdba6c8eb2b43d2fa01c743be1b9273ab1eaf6c233df078d705",
)
http_archive(
    name = "bazel_gazelle",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.16.0/bazel-gazelle-0.16.0.tar.gz",
    sha256 = "7949fc6cc17b5b191103e97481cf8889217263acf52e00b560683413af204fcb",
)

load("@io_bazel_rules_go//go:def.bzl", "go_rules_dependencies", "go_register_toolchains")
go_rules_dependencies()
go_register_toolchains(go_version="1.11.4")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
gazelle_dependencies()

# Load bazel_toolchain to support Remote Build Execution.
# See releases at https://releases.bazel.build/bazel-toolchains.html
http_archive(
  name = "bazel_toolchains",
  urls = [
    "https://mirror.bazel.build/github.com/bazelbuild/bazel-toolchains/archive/31b5dc8c4e9c7fd3f5f4d04c6714f2ce87b126c1.tar.gz",
    "https://github.com/bazelbuild/bazel-toolchains/archive/31b5dc8c4e9c7fd3f5f4d04c6714f2ce87b126c1.tar.gz",
  ],
  strip_prefix = "bazel-toolchains-31b5dc8c4e9c7fd3f5f4d04c6714f2ce87b126c1",
  sha256 = "07a81ee03f5feae354c9f98c884e8e886914856fb2b6a63cba4619ef10aaaf0b",
)

# External repositories, in sorted order.
go_repository(
    name = "com_github_cenkalti_backoff",
    importpath = "github.com/cenkalti/backoff",
    commit = "66e726b43552c0bab0539b28e640b89fd6862115",
)

go_repository(
    name = "com_github_gofrs_flock",
    importpath = "github.com/gofrs/flock",
    commit = "886344bea0798d02ff3fae16a922be5f6b26cee0"
)

go_repository(
    name = "com_github_golang_mock",
    importpath = "github.com/golang/mock",
    commit = "600781dde9cca80734169b9e969d9054ccc57937",
)

go_repository(
    name = "com_github_google_go-cmp",
    importpath = "github.com/google/go-cmp",
    commit = "3af367b6b30c263d47e8895973edcca9a49cf029",
)

go_repository(
    name = "com_github_google_subcommands",
    importpath = "github.com/google/subcommands",
    commit = "ce3d4cfc062faac7115d44e5befec8b5a08c3faa",
)

go_repository(
    name = "com_github_google_uuid",
    importpath = "github.com/google/uuid",
    commit = "dec09d789f3dba190787f8b4454c7d3c936fed9e",
)

go_repository(
    name = "com_github_kr_pty",
    importpath = "github.com/kr/pty",
    commit = "282ce0e5322c82529687d609ee670fac7c7d917c",
)

go_repository(
    name = "com_github_opencontainers_runtime-spec",
    importpath = "github.com/opencontainers/runtime-spec",
    commit = "b2d941ef6a780da2d9982c1fb28d77ad97f54fc7",
)

go_repository(
    name = "com_github_syndtr_gocapability",
    importpath = "github.com/syndtr/gocapability",
    commit = "d98352740cb2c55f81556b63d4a1ec64c5a319c2",
)

go_repository(
    name = "com_github_vishvananda_netlink",
    importpath = "github.com/vishvananda/netlink",
    commit = "d35d6b58e1cb692b27b94fc403170bf44058ac3e",
)

go_repository(
    name = "com_github_vishvananda_netns",
    importpath = "github.com/vishvananda/netns",
    commit = "be1fbeda19366dea804f00efff2dd73a1642fdcc",
)

go_repository(
    name = "org_golang_x_net",
    importpath = "golang.org/x/net",
    commit = "b3c676e531a6dc479fa1b35ac961c13f5e2b4d2e",
)

go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    commit = "0dd5e194bbf5eb84a39666eb4c98a4d007e4203a",
)

go_repository(
    name = "com_github_google_btree",
    importpath = "github.com/google/btree",
    commit = "4030bb1f1f0c35b30ca7009e9ebd06849dd45306",
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
