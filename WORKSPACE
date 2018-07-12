# Load go bazel rules and gazelle.
http_archive(
    name = "io_bazel_rules_go",
    url = "https://github.com/bazelbuild/rules_go/releases/download/0.13.0/rules_go-0.13.0.tar.gz",
    sha256 = "ba79c532ac400cefd1859cbc8a9829346aa69e3b99482cd5a54432092cbc3933",
)
http_archive(
    name = "bazel_gazelle",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.13.0/bazel-gazelle-0.13.0.tar.gz",
    sha256 = "bc653d3e058964a5a26dcad02b6c72d7d63e6bb88d94704990b908a1445b8758",
)
load("@io_bazel_rules_go//go:def.bzl", "go_rules_dependencies", "go_register_toolchains")
go_rules_dependencies()
go_register_toolchains(go_version="1.10.3")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
gazelle_dependencies()

# Add dependencies on external repositories.
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
    commit = "33e07d32887e1e06b7c025f27ce52f62c7990bc0",
)
