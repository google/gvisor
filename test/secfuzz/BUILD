load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "secfuzz",
    testonly = 1,
    srcs = [
        "secfuzz.go",
        "secfuzz_covermeup.go",
        "secfuzz_nocoverageguidance.go",
    ],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/sentry",
        "//pkg/atomicbitops",
        "//pkg/bpf",
        "//pkg/seccomp",
        "//pkg/sync",
    ],
)

genrule(
    name = "secfuzz_covermeup",
    srcs = ["secfuzz_covermeup.tmpl.go"],
    outs = ["secfuzz_covermeup.go"],
    cmd = (
        "  while IFS= read -r line; do" +
        "    if echo \"$$line\" | grep -q 'GENERATED_LINES_INSERTED_HERE_THIS_IS_A_LOAD_BEARING_COMMENT'; then" +
        "      while IFS= read -r i; do" +
        "        echo -e \"\\\\tcase $$(( $$i + 1 )):\";" +
        "        echo -e \"\\\\t\\\\tif covered[$$i] {\";" +
        "        echo -e \"\\\\t\\\\t\\\\tfuzzee.coverage[$$i].Store(true)\";" +
        "        echo -e \"\\\\t\\\\t}\";" +
        "        echo -e \"\\\\t\\\\tfallthrough\";" +
        "      done < <(awk 'BEGIN{for (i = 4095; i >= 1; i --) print i}');" +
        "    else" +
        "      echo \"$$line\";" +
        "    fi;" +
        "  done" +
        "  < $(location :secfuzz_covermeup.tmpl.go)" +
        "  > $@"
    ),
)
