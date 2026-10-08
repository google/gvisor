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
    embed = [":abslbuild"],
    local = True,
    nogo = False,
    tags = [
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
        "//pkg/atomicbitops",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/api/resource:go_default_library",
        "@org_golang_x_time//rate:go_default_library",
    ],
)

go_test(
    name = "startup_test",
    srcs = ["startup_test.go"],
    embed = [":startup"],
    local = True,
    nogo = False,
    tags = [
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
    name = "openclaw",
    testonly = True,
    srcs = ["openclaw.go"],
    nogo = False,
    deps = [
        "//runsc/flag",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/api/resource:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/intstr:go_default_library",
        "@io_k8s_client_go//kubernetes:go_default_library",
    ],
)

go_test(
    name = "openclaw_test",
    srcs = ["openclaw_test.go"],
    embed = [":openclaw"],
    local = True,
    nogo = False,
    tags = [
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
    embed = [":redis"],
    local = True,
    nogo = False,
    tags = [
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
    embed = [":ffmpeg"],
    local = True,
    nogo = False,
    tags = [
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
    embed = [":grpc"],
    local = True,
    nogo = False,
    tags = [
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
    embed = [":nginx"],
    local = True,
    nogo = False,
    tags = [
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
    embed = [":postgresql"],
    local = True,
    nogo = False,
    tags = [
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
    embed = [":tensorflow"],
    local = True,
    nogo = False,
    tags = [
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
    embed = [":wordpress"],
    local = True,
    nogo = False,
    tags = [
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
        "//test/kubernetes/benchmarks/utils",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/intstr:go_default_library",
    ],
)

go_test(
    name = "ollama_test",
    srcs = ["ollama_test.go"],
    embed = [":ollama"],
    local = True,
    nogo = False,
    tags = [
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
    name = "triton",
    testonly = True,
    srcs = ["triton.go"],
    embedsrcs = [
        "//test/kubernetes/benchmarks/resources:files",  # keep
    ],
    nogo = False,
    deps = [
        "//pkg/sync",
        "//test/gpu/triton",
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmarks/utils",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/intstr:go_default_library",
    ],
)

go_test(
    name = "triton_test",
    srcs = ["triton_test.go"],
    embed = [":triton"],
    local = True,
    nogo = False,
    tags = [
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
    name = "sglang",
    testonly = True,
    srcs = ["sglang.go"],
    embedsrcs = [
        "//test/kubernetes/benchmarks/resources:files",  # keep
    ],
    nogo = False,
    deps = [
        "//pkg/sync",
        "//test/gpu/sglang",
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmarks/utils",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/intstr:go_default_library",
    ],
)

go_test(
    name = "sglang_test",
    srcs = ["sglang_test.go"],
    embed = [":sglang"],
    local = True,
    nogo = False,
    tags = [
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
    embed = [":stablediffusion"],
    local = True,
    nogo = False,
    tags = [
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
    embed = [":gsutil"],
    local = True,
    nogo = False,
    tags = [
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
    embed = [":rubydev"],
    local = True,
    tags = [
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
    name = "vllm",
    testonly = True,
    srcs = ["vllm.go"],
    embedsrcs = [
        "//test/kubernetes/benchmarks/resources:files",  # keep
    ],
    nogo = False,
    deps = [
        "//pkg/sync",
        "//test/kubernetes",
        "//test/kubernetes/benchmarks/profiling",
        "//test/kubernetes/benchmarks/utils",
        "//test/kubernetes/benchmetric",
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/testcluster",
        "//test/tpu/vllm",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/intstr:go_default_library",
    ],
)

go_test(
    name = "vllm_test",
    srcs = ["vllm_test.go"],
    embed = [":vllm"],
    local = True,
    nogo = False,
    tags = [
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/kubernetes/k8sctx",
        "//test/kubernetes/k8sctx/kubectlctx",
        "//test/kubernetes/testcluster",
    ],
)
