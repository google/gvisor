load("//tools:defs.bzl", "go_test", "pkg_tar")

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

[pkg_tar(
    name = "%s_tar" % (src[src.index(":") + 1:],),
    testonly = True,
    srcs = [src],
    extension = "tar.bz2",
) for src in _ALL_BENCHMARK_TARGETS]

filegroup(
    name = "all_benchmark_test_binaries_tar",
    testonly = True,
    srcs = ["%s_tar" % (src[src.index(":") + 1:],) for src in _ALL_BENCHMARK_TARGETS],
)

go_test(
    name = "abslbuild_test",
    srcs = ["abslbuild_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
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
    name = "startup_test",
    srcs = ["startup_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
    ],
)

go_test(
    name = "redis_test",
    srcs = ["redis_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
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
    name = "ruby_dev_test",
    srcs = ["ruby_dev_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
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
    name = "ffmpeg_test",
    srcs = ["ffmpeg_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
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
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
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
    name = "nginx_test",
    srcs = ["nginx_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
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
    name = "postgresql_test",
    srcs = ["postgresql_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
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
    name = "tensorflow_test",
    srcs = ["tensorflow_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
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
    name = "wordpress_test",
    srcs = ["wordpress_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
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
    name = "pytorch_test",
    srcs = ["pytorch_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
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
    name = "ollama_test",
    srcs = ["ollama_test.go"],
    embedsrcs = [
        "//test/kubernetes/benchmarks/resources:files",  # keep
    ],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/gpu/ollama",
        "//test/kubernetes",
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
    name = "stablediffusion_test",
    srcs = ["stablediffusion_test.go"],
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/gpu/stablediffusion",
        "//test/kubernetes",
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
    nogo = False,
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
    ],
)
