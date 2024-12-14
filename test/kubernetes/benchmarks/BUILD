load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

_PACKAGE = "//test/kubernetes/benchmarks"

_ALL_BENCHMARK_TARGETS = [
    "%s:%s" %
    (
        _PACKAGE,
        f.replace(".go", ""),
    )
    for f in glob(["**/*_test.go"])
]

genquery(
    name = "all_benchmark_targets",
    testonly = True,
    expression = " union ".join(_ALL_BENCHMARK_TARGETS),
    scope = _ALL_BENCHMARK_TARGETS,
)

filegroup(
    name = "all_benchmark_test_binaries",
    testonly = True,
    srcs = _ALL_BENCHMARK_TARGETS,
)

go_library(
    name = "abslbuild",
    testonly = True,
    srcs = ["abslbuild.go"],
    nogo = False,
    deps = [
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
    ],
)

go_test(
    name = "abslbuild_test",
    srcs = ["abslbuild_test.go"],
    library = ":abslbuild",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "startup",
    testonly = True,
    srcs = ["startup.go"],
    nogo = False,
    deps = [
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
    ],
)

go_test(
    name = "startup_test",
    srcs = ["startup_test.go"],
    library = ":startup",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "redis",
    testonly = True,
    srcs = ["redis.go"],
    nogo = False,
    deps = [
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/intstr:go_default_library",
    ],
)

go_test(
    name = "redis_test",
    srcs = ["redis_test.go"],
    library = ":redis",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "ffmpeg",
    testonly = True,
    srcs = ["ffmpeg.go"],
    nogo = False,
    deps = [
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
    ],
)

go_test(
    name = "ffmpeg_test",
    srcs = ["ffmpeg_test.go"],
    library = ":ffmpeg",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "grpc",
    testonly = True,
    srcs = ["grpc.go"],
    nogo = False,
    deps = [
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
    ],
)

go_test(
    name = "grpc_test",
    srcs = ["grpc_test.go"],
    library = ":grpc",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "nginx",
    testonly = True,
    srcs = ["nginx.go"],
    nogo = False,
    deps = [
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/httpbench",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/intstr:go_default_library",
    ],
)

go_test(
    name = "nginx_test",
    srcs = ["nginx_test.go"],
    library = ":nginx",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "postgresql",
    testonly = True,
    srcs = ["postgresql.go"],
    nogo = False,
    deps = [
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/intstr:go_default_library",
    ],
)

go_test(
    name = "postgresql_test",
    srcs = ["postgresql_test.go"],
    library = ":postgresql",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "tensorflow",
    testonly = True,
    srcs = ["tensorflow.go"],
    nogo = False,
    deps = [
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
    ],
)

go_test(
    name = "tensorflow_test",
    srcs = ["tensorflow_test.go"],
    library = ":tensorflow",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "wordpress",
    testonly = True,
    srcs = ["wordpress.go"],
    nogo = False,
    deps = [
        "//test/kubernetes/benchmarks/httpbench",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/intstr:go_default_library",
    ],
)

go_test(
    name = "wordpress_test",
    srcs = ["wordpress_test.go"],
    library = ":wordpress",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "pytorch",
    testonly = True,
    srcs = ["pytorch.go"],
    nogo = False,
    deps = [
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
    ],
)

go_test(
    name = "pytorch_test",
    srcs = ["pytorch_test.go"],
    library = ":pytorch",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "ollama",
    testonly = True,
    srcs = ["ollama.go"],
    embedsrcs = [
        "//test/kubernetes/benchmarks/resources:files",  # keep
    ],
    nogo = False,
    deps = [
        "//pkg/sync",
        "//test/gpu/ollama",
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/api/resource:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/intstr:go_default_library",
    ],
)

go_test(
    name = "ollama_test",
    srcs = ["ollama_test.go"],
    library = ":ollama",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "stablediffusion",
    testonly = True,
    srcs = ["stablediffusion.go"],
    nogo = False,
    deps = [
        "//test/gpu/stablediffusion",
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
    ],
)

go_test(
    name = "stablediffusion_test",
    srcs = ["stablediffusion_test.go"],
    library = ":stablediffusion",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "gsutil",
    testonly = True,
    srcs = ["gsutil.go"],
    nogo = False,
    deps = [
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
    ],
)

go_test(
    name = "gsutil_test",
    srcs = ["gsutil_test.go"],
    library = ":gsutil",
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)

go_library(
    name = "rubydev",
    testonly = True,
    srcs = ["rubydev.go"],
    nogo = False,
    deps = [
        "//test/benchmarks/tools",
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
    ],
)

go_test(
    name = "rubydev_test",
    srcs = ["rubydev_test.go"],
    library = ":rubydev",
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)
