load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

config_setting(
    name = "metric_server_elided",
    values = {
        "compilation_mode": "fastbuild",
    },
)

# @unused
glaze_ignore = [
    "embed_metricserver.go",
    "embed_metricserver_elided.go",
]

# Use either embed_metricserver_elided.go (fastbuild) or embed_metricserver.go
# so that fastbuild builds do not embed the large metric server binary.
genrule(
    name = "embed_metricserver_cmd",
    srcs = select({
        ":metric_server_elided": ["embed_metricserver_elided.go"],
        "//conditions:default": ["embed_metricserver.go"],
    }),
    outs = ["embed_metricserver_gen.go"],
    cmd = "cat < $(SRCS) > $(OUTS)",
)

go_library(
    name = "embed",
    srcs = [
        "embed.go",
        "embed_metricserver_gen.go",
    ],
    stateify = False,
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//runsc/checkpointgofer",
        "//runsc/gvisorbinaries",
    ] + select({
        ":metric_server_elided": [],
        "//conditions:default": [
            "//runsc/cmd/metricserver",
        ],
    }),
)
