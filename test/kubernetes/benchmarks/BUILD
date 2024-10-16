load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "abslbuild_test",
    srcs = ["abslbuild_test.go"],
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

go_test(
    name = "startup_test",
    srcs = ["startup_test.go"],
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
    name = "ruby_dev_test",
    srcs = ["ruby_dev_test.go"],
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/benchmarks/tools",
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

go_test(
    name = "grpc_test",
    srcs = ["grpc_test.go"],
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

go_test(
    name = "nginx_test",
    srcs = ["nginx_test.go"],
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
    name = "postgresql_test",
    srcs = ["postgresql_test.go"],
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

go_test(
    name = "wordpress_test",
    srcs = ["wordpress_test.go"],
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
    name = "ollama_test",
    srcs = ["ollama_test.go"],
    embedsrcs = [
        "//test/kubernetes/benchmarks/resources:files",  # keep
    ],
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/gpu/ollama",
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
    tags = [
        "local",
        "noguitar",
        "notap",
    ],
    deps = [
        "//test/gpu/stablediffusion",
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
