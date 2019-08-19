# Load go bazel rules and gazelle.
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "313f2c7a23fecc33023563f082f381a32b9b7254f727a7dd2d6380ccc6dfe09b",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/rules_go/releases/download/0.19.3/rules_go-0.19.3.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/0.19.3/rules_go-0.19.3.tar.gz",
    ],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "be9296bfd64882e3c08e3283c58fcb461fa6dd3c171764fcc4cf322f60615a9b",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/bazel-gazelle/releases/download/0.18.1/bazel-gazelle-0.18.1.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.18.1/bazel-gazelle-0.18.1.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_register_toolchains(
    go_version = "1.12.9",
    nogo = "@//:nogo",
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

gazelle_dependencies()

# Load protobuf dependencies.
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(
    name = "com_google_protobuf",
    commit = "09745575a923640154bcf307fba8aedff47f240a",
    remote = "https://github.com/protocolbuffers/protobuf",
    shallow_since = "1558721209 -0700",
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

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
    importpath = "github.com/cenkalti/backoff",
    sum = "h1:+FKjzBIdfBHYDvxCv+djmDJdes/AoDtg8gpcxowBlF8=",
    version = "v0.0.0-20190506075156-2146c9339422",
)

go_repository(
    name = "com_github_gofrs_flock",
    importpath = "github.com/gofrs/flock",
    sum = "h1:JFTFz3HZTGmgMz4E1TabNBNJljROSYgja1b4l50FNVs=",
    version = "v0.6.1-0.20180915234121-886344bea079",
)

go_repository(
    name = "com_github_golang_mock",
    importpath = "github.com/golang/mock",
    sum = "h1:qGJ6qTW+x6xX/my+8YUVl4WNpX9B7+/l2tRsHGZ7f2s=",
    version = "v1.3.1",
)

go_repository(
    name = "com_github_google_go-cmp",
    importpath = "github.com/google/go-cmp",
    sum = "h1:+dTQ8DZQJz0Mb/HjFlkptS1FeQ4cWSnN941F8aEG4SQ=",
    version = "v0.2.0",
)

go_repository(
    name = "com_github_google_subcommands",
    importpath = "github.com/google/subcommands",
    sum = "h1:GZGUPQiZfYrd9uOqyqwbQcHPkz/EZJVkZB1MkaO9UBI=",
    version = "v0.0.0-20190508160503-636abe8753b8",
)

go_repository(
    name = "com_github_google_uuid",
    importpath = "github.com/google/uuid",
    sum = "h1:rXQlD9GXkjA/PQZhmEaF/8Pj/sJfdZJK7GJG0gkS8I0=",
    version = "v0.0.0-20171129191014-dec09d789f3d",
)

go_repository(
    name = "com_github_kr_pty",
    importpath = "github.com/kr/pty",
    sum = "h1:VkoXIwSboBpnk99O/KFauAEILuNHv5DVFKZMBN/gUgw=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_opencontainers_runtime-spec",
    importpath = "github.com/opencontainers/runtime-spec",
    sum = "h1:d9F+LNYwMyi3BDN4GzZdaSiq4otb8duVEWyZjeUtOQI=",
    version = "v0.1.2-0.20171211145439-b2d941ef6a78",
)

go_repository(
    name = "com_github_syndtr_gocapability",
    importpath = "github.com/syndtr/gocapability",
    sum = "h1:b6uOv7YOFK0TYG7HtkIgExQo+2RdLuwRft63jn2HWj8=",
    version = "v0.0.0-20180916011248-d98352740cb2",
)

go_repository(
    name = "com_github_vishvananda_netlink",
    importpath = "github.com/vishvananda/netlink",
    sum = "h1:/Tdc23Arz1OtdIsBY2utWepGRQ9fEAJlhkdoLzWMK8Q=",
    version = "v1.0.1-0.20190318003149-adb577d4a45e",
)

go_repository(
    name = "com_github_vishvananda_netns",
    importpath = "github.com/vishvananda/netns",
    sum = "h1:J9gO8RJCAFlln1jsvRba/CWVUnMHwObklfxxjErl1uk=",
    version = "v0.0.0-20171111001504-be1fbeda1936",
)

go_repository(
    name = "org_golang_x_crypto",
    importpath = "golang.org/x/crypto",
    sum = "h1:VklqNMn3ovrHsnt90PveolxSbWFaJdECFbxSq0Mqo2M=",
    version = "v0.0.0-20190308221718-c2843e01d9a2",
)

go_repository(
    name = "org_golang_x_net",
    importpath = "golang.org/x/net",
    sum = "h1:oWX7TPOiFAMXLq8o0ikBYfCJVlRHBcsciT5bXOrH628=",
    version = "v0.0.0-20190311183353-d8887717615a",
)

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    sum = "h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=",
    version = "v0.3.0",
)

go_repository(
    name = "org_golang_x_tools",
    commit = "36563e24a262",
    importpath = "golang.org/x/tools",
)

go_repository(
    name = "org_golang_x_sync",
    importpath = "golang.org/x/sync",
    sum = "h1:8gQV6CLnAEikrhgkHFbMAEhagSSnXWGV915qUMm9mrU=",
    version = "v0.0.0-20190423024810-112230192c58",
)

go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    sum = "h1:1BGLXjeY4akVXGgbC9HugT3Jv3hCI0z56oJR5vAMgBU=",
    version = "v0.0.0-20190215142949-d0b11bdaac8a",
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
    sum = "h1:0udJVsspx3VBr5FwtLhQQtuAsVc79tTq0ocGIPAU6qo=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_golang_protobuf",
    importpath = "github.com/golang/protobuf",
    sum = "h1:YF8+flBXS5eO826T4nzqPrxfhQThhXl0YzfuUPu4SBg=",
    version = "v1.3.1",
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
