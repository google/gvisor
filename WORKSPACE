# Load go bazel rules and gazelle.
http_archive(
    name = "io_bazel_rules_go",
    url = "https://github.com/bazelbuild/rules_go/releases/download/0.15.4/rules_go-0.15.4.tar.gz",
    sha256 = "7519e9e1c716ae3c05bd2d984a42c3b02e690c5df728dc0a84b23f90c355c5a1",
)
http_archive(
    name = "bazel_gazelle",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.14.0/bazel-gazelle-0.14.0.tar.gz",
    sha256 = "c0a5739d12c6d05b6c1ad56f2200cb0b57c5a70e03ebd2f7b87ce88cabf09c7b",
)
load("@io_bazel_rules_go//go:def.bzl", "go_rules_dependencies", "go_register_toolchains")
go_rules_dependencies()
go_register_toolchains(go_version="1.11.1")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
gazelle_dependencies()

# Add dependencies on external repositories.
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
    name = "com_github_syndtr_gocapability",
    importpath = "github.com/syndtr/gocapability",
    commit = "d98352740cb2c55f81556b63d4a1ec64c5a319c2",
)
