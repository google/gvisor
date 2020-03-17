load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

# Load go bazel rules and gazelle.
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "94f90feaa65c9cdc840cd21f67d967870b5943d684966a47569da8073e42063d",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.22.0/rules_go-v0.22.0.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.22.0/rules_go-v0.22.0.tar.gz",
    ],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "d8c45ee70ec39a57e7a05e5027c32b1576cc7f16d9dd37135b0eddde45cf1b10",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/bazel-gazelle/releases/download/v0.20.0/bazel-gazelle-v0.20.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.20.0/bazel-gazelle-v0.20.0.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains(
    go_version = "1.14",
    nogo = "@//:nogo",
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

gazelle_dependencies()

# TODO(gvisor.dev/issue/1876): Move the statement to "External repositories"
# block below once 1876 is fixed.
#
# The com_google_protobuf repository below would trigger downloading a older
# version of org_golang_x_sys. If putting this repository statment in a place
# after that of the com_google_protobuf, this statement will not work as
# expectd to download a new version of org_golang_x_sys.
go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    sum = "h1:uYVVQ9WP/Ds2ROhcaGPeIdVq0RIXVLwsHlnvJ+cT1So=",
    version = "v0.0.0-20200302150141-5c8b2ff67527",
)

# Load C++ rules.
http_archive(
    name = "rules_cc",
    sha256 = "67412176974bfce3f4cf8bdaff39784a72ed709fc58def599d1f68710b58d68b",
    strip_prefix = "rules_cc-b7fe9697c0c76ab2fd431a891dbb9a6a32ed7c3e",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_cc/archive/b7fe9697c0c76ab2fd431a891dbb9a6a32ed7c3e.zip",
        "https://github.com/bazelbuild/rules_cc/archive/b7fe9697c0c76ab2fd431a891dbb9a6a32ed7c3e.zip",
    ],
)

# Load protobuf dependencies.
http_archive(
    name = "rules_proto",
    sha256 = "602e7161d9195e50246177e7c55b2f39950a9cf7366f74ed5f22fd45750cd208",
    strip_prefix = "rules_proto-97d8af4dc474595af3900dd85cb3a29ad28cc313",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_proto/archive/97d8af4dc474595af3900dd85cb3a29ad28cc313.tar.gz",
        "https://github.com/bazelbuild/rules_proto/archive/97d8af4dc474595af3900dd85cb3a29ad28cc313.tar.gz",
    ],
)

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()

rules_proto_toolchains()

# Load python dependencies.
git_repository(
    name = "rules_python",
    commit = "abc4869e02fe9b3866942e89f07b7341f830e805",
    remote = "https://github.com/bazelbuild/rules_python.git",
    shallow_since = "1583341286 -0500",
)

load("@rules_python//python:pip.bzl", "pip_import")

pip_import(
    name = "pydeps",
    python_interpreter = "python3",
    requirements = "//benchmarks:requirements.txt",
)

load("@pydeps//:requirements.bzl", "pip_install")

pip_install()

# Load bazel_toolchain to support Remote Build Execution.
# See releases at https://releases.bazel.build/bazel-toolchains.html
http_archive(
    name = "bazel_toolchains",
    sha256 = "b5a8039df7119d618402472f3adff8a1bd0ae9d5e253f53fcc4c47122e91a3d2",
    strip_prefix = "bazel-toolchains-2.1.1",
    urls = [
        "https://github.com/bazelbuild/bazel-toolchains/releases/download/2.1.1/bazel-toolchains-2.1.1.tar.gz",
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-toolchains/archive/2.1.1.tar.gz",
    ],
)

# Creates a default toolchain config for RBE.
load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")

rbe_autoconfig(name = "rbe_default")

http_archive(
    name = "rules_pkg",
    sha256 = "5bdc04987af79bd27bc5b00fe30f59a858f77ffa0bd2d8143d5b31ad8b1bd71c",
    url = "https://github.com/bazelbuild/rules_pkg/releases/download/0.2.0/rules_pkg-0.2.0.tar.gz",
)

load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")

rules_pkg_dependencies()

# Container rules.
http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "14ac30773fdb393ddec90e158c9ec7ebb3f8a4fd533ec2abbfd8789ad81a284b",
    strip_prefix = "rules_docker-0.12.1",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.12.1/rules_docker-v0.12.1.tar.gz"],
)

load(
    "@io_bazel_rules_docker//repositories:repositories.bzl",
    container_repositories = "repositories",
)

container_repositories()

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")

container_deps()

load(
    "@io_bazel_rules_docker//container:container.bzl",
    "container_pull",
)

# This container is built from the Dockerfile in test/iptables/runner.
container_pull(
    name = "iptables-test",
    digest = "sha256:a137d692a2eb9fc7bf95c5f4a568da090e2c31098e93634421ed88f3a3f1db65",
    registry = "gcr.io",
    repository = "gvisor-presubmit/iptables-test",
)

load(
    "@io_bazel_rules_docker//go:image.bzl",
    _go_image_repos = "repositories",
)

_go_image_repos()

# Load C++ grpc rules.
http_archive(
    name = "com_github_grpc_grpc",
    sha256 = "2fcb7f1ab160d6fd3aaade64520be3e5446fc4c6fa7ba6581afdc4e26094bd81",
    strip_prefix = "grpc-1.26.0",
    urls = [
        "https://github.com/grpc/grpc/archive/v1.26.0.tar.gz",
    ],
)
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")
grpc_deps()
load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")
grpc_extra_deps()

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
    name = "com_github_imdario_mergo",
    importpath = "github.com/imdario/mergo",
    version = "v0.3.8",
    sum = "h1:CGgOkSJeqMRmt0D9XLWExdT4m4F1vd3FV3VPt+0VxkQ=",
)

go_repository(
    name = "com_github_kr_pretty",
    importpath = "github.com/kr/pretty",
    sum = "h1:s5hAObm+yFO5uHYt5dYjxi2rXrsnmRpJx4OYvIWUaQs=",
    version = "v0.2.0",
)

go_repository(
    name = "com_github_kr_pty",
    importpath = "github.com/kr/pty",
    sum = "h1:VkoXIwSboBpnk99O/KFauAEILuNHv5DVFKZMBN/gUgw=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_kr_text",
    importpath = "github.com/kr/text",
    sum = "h1:45sCR5RtlFHMR4UwH9sdQ5TC8v0qDQCHnXt+kaKSTVE=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_mohae_deepcopy",
    importpath = "github.com/mohae/deepcopy",
    commit = "c48cc78d482608239f6c4c92a4abd87eb8761c90",
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
    name = "org_golang_google_grpc",
    build_file_proto_mode = "disable",
    importpath = "google.golang.org/grpc",
    sum = "h1:zvIju4sqAGvwKspUQOhwnpcqSbzi7/H6QomNNjTL4sk=",
    version = "v1.27.1",
)

go_repository(
    name = "in_gopkg_check_v1",
    importpath = "gopkg.in/check.v1",
    sum = "h1:YR8cESwS4TdDjEe65xsg0ogRM/Nc3DYOhEAlW+xobZo=",
    version = "v1.0.0-20190902080502-41f04d3bba15",
)

go_repository(
    name = "org_golang_x_crypto",
    importpath = "golang.org/x/crypto",
    sum = "h1:ObdrDkeb4kJdCP557AjRjq69pTHfNouLtWZG7j9rPN8=",
    version = "v0.0.0-20191011191535-87dc89f01550",
)

go_repository(
    name = "org_golang_x_mod",
    importpath = "golang.org/x/mod",
    sum = "h1:p1YOIz9H/mGN8k1XkaV5VFAq9+zhN9Obefv439UwRhI=",
    version = "v0.2.1-0.20200224194123-e5e73c1b9c72",
)

go_repository(
    name = "org_golang_x_net",
    importpath = "golang.org/x/net",
    sum = "h1:R/3boaszxrf1GEUWTVDzSKVwLmSJpwZ1yqXm8j0v2QI=",
    version = "v0.0.0-20190620200207-3b0461eec859",
)

go_repository(
    name = "org_golang_x_sync",
    importpath = "golang.org/x/sync",
    sum = "h1:8gQV6CLnAEikrhgkHFbMAEhagSSnXWGV915qUMm9mrU=",
    version = "v0.0.0-20190423024810-112230192c58",
)

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    sum = "h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=",
    version = "v0.3.0",
)

go_repository(
    name = "org_golang_x_time",
    importpath = "golang.org/x/time",
    sum = "h1:/5xXl8Y5W96D+TtHSlonuFqGHIWVuyCkGJLwGh9JJFs=",
    version = "v0.0.0-20191024005414-555d28b269f0",
)

go_repository(
    name = "org_golang_x_tools",
    importpath = "golang.org/x/tools",
    sum = "h1:aZzprAO9/8oim3qStq3wc1Xuxx4QmAGriC4VU4ojemQ=",
    version = "v0.0.0-20191119224855-298f0cb1881e",
)

go_repository(
    name = "org_golang_x_xerrors",
    importpath = "golang.org/x/xerrors",
    sum = "h1:E7g+9GITq07hpfrRu66IVDexMakfv52eLZ2CXBWiKr4=",
    version = "v0.0.0-20191204190536-9bdfabe68543",
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

go_repository(
    name = "com_github_google_go-github",
    importpath = "github.com/google/go-github",
    sum = "h1:N0LgJ1j65A7kfXrZnUDaYCs/Sf4rEjNlfyDHW9dolSY=",
    version = "v17.0.0",
)

go_repository(
    name = "org_golang_x_oauth2",
    importpath = "golang.org/x/oauth2",
    sum = "h1:pE8b58s1HRDMi8RDc79m0HISf9D4TzseP40cEA6IGfs=",
    version = "v0.0.0-20191202225959-858c2ad4c8b6",
)

go_repository(
    name = "com_github_google_go-querystring",
    importpath = "github.com/google/go-querystring",
    sum = "h1:Xkwi/a1rcvNg1PPYe5vI8GbeBY/jrVuDX5ASuANWTrk=",
    version = "v1.0.0",
)

# System Call test dependencies.
http_archive(
    name = "com_google_absl",
    sha256 = "56775f1283a59e6274c28d99981a9717ff4e0b1161e9129fdb2fcf22531d8d93",
    strip_prefix = "abseil-cpp-a0d1e098c2f99694fa399b175a7ccf920762030e",
    urls = [
        "https://mirror.bazel.build/github.com/abseil/abseil-cpp/archive/a0d1e098c2f99694fa399b175a7ccf920762030e.tar.gz",
        "https://github.com/abseil/abseil-cpp/archive/a0d1e098c2f99694fa399b175a7ccf920762030e.tar.gz",
    ],
)

http_archive(
    name = "com_google_googletest",
    sha256 = "0a10bea96d8670e5eef948d79d824162b1577bb7889539e49ec786bfc3e48912",
    strip_prefix = "googletest-565f1b848215b77c3732bca345fe76a0431d8b34",
    urls = [
        "https://mirror.bazel.build/github.com/google/googletest/archive/565f1b848215b77c3732bca345fe76a0431d8b34.tar.gz",
        "https://github.com/google/googletest/archive/565f1b848215b77c3732bca345fe76a0431d8b34.tar.gz",
    ],
)

http_archive(
    name = "com_google_benchmark",
    sha256 = "3c6a165b6ecc948967a1ead710d4a181d7b0fbcaa183ef7ea84604994966221a",
    strip_prefix = "benchmark-1.5.0",
    urls = [
        "https://mirror.bazel.build/github.com/google/benchmark/archive/v1.5.0.tar.gz",
        "https://github.com/google/benchmark/archive/v1.5.0.tar.gz",
    ],
)
