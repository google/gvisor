# Load go bazel rules and gazelle.
http_archive(
    name = "io_bazel_rules_go",
    url = "https://github.com/bazelbuild/rules_go/releases/download/0.16.0/rules_go-0.16.0.tar.gz",
    sha256 = "ee5fe78fe417c685ecb77a0a725dc9f6040ae5beb44a0ba4ddb55453aad23a8a",
)
http_archive(
    name = "bazel_gazelle",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.15.0/bazel-gazelle-0.15.0.tar.gz",
    sha256 = "6e875ab4b6bf64a38c352887760f21203ab054676d9c1b274963907e0768740d",
)
load("@io_bazel_rules_go//go:def.bzl", "go_rules_dependencies", "go_register_toolchains")
go_rules_dependencies()
go_register_toolchains(go_version="1.11.1")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
gazelle_dependencies()

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
