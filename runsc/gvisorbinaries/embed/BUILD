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

# Elides all embedded sidecar binaries, for installations that ship on-disk
# sidecar binaries (in gvisor-bin/) and don't want runsc to carry embedded
# copies. Build with `--define gvisor_embed_sidecars=false`.
config_setting(
    name = "sidecars_elided",
    values = {
        "define": "gvisor_embed_sidecars=false",
    },
)

# @unused
glaze_ignore = [
    "embed_checkpointgofer.go",
    "embed_checkpointgofer_elided.go",
    "embed_metricserver.go",
    "embed_metricserver_elided.go",
]

# Use either embed_metricserver_elided.go (fastbuild, or sidecar embedding
# disabled) or embed_metricserver.go, so that fastbuild builds do not embed
# the large metric server binary.
genrule(
    name = "embed_metricserver_cmd",
    srcs = select({
        ":metric_server_elided": ["embed_metricserver_elided.go"],
        ":sidecars_elided": ["embed_metricserver_elided.go"],
        "//conditions:default": ["embed_metricserver.go"],
    }),
    outs = ["embed_metricserver_gen.go"],
    cmd = "cat < $(SRCS) > $(OUTS)",
)

# Use either embed_checkpointgofer_elided.go (sidecar embedding disabled) or
# embed_checkpointgofer.go.
genrule(
    name = "embed_checkpointgofer_cmd",
    srcs = select({
        ":sidecars_elided": ["embed_checkpointgofer_elided.go"],
        "//conditions:default": ["embed_checkpointgofer.go"],
    }),
    outs = ["embed_checkpointgofer_gen.go"],
    cmd = "cat < $(SRCS) > $(OUTS)",
)

go_library(
    name = "embed",
    srcs = [
        "embed.go",
        "embed_checkpointgofer_gen.go",
        "embed_metricserver_gen.go",
    ],
    stateify = False,
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//runsc/gvisorbinaries",
    ] + select({
        ":sidecars_elided": [],
        "//conditions:default": [
            "//runsc/checkpointgofer",
        ],
    }) + select({
        ":metric_server_elided": [],
        ":sidecars_elided": [],
        "//conditions:default": [
            "//runsc/cmd/metricserver",
        ],
    }),
)
