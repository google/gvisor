"""Macro for precompiling seccomp-bpf programs."""

load("//tools:defs.bzl", "go_binary", "select_arch")

def precompiled_seccomp_rules(
        name,
        programs_to_compile_go_library,
        programs_to_compile_go_import,
        out,
        out_package_name,
        exclude_in_fastbuild = False,
        tags = []):
    """Generates a Go source file containing precompiled seccomp-bpf programs.

    Args:
        name: Name of the generated source target.
        programs_to_compile_go_library: go_library target which describes the
            set of seccomp-bpf programs that you wish to precompile. This must
            define the following package-level function:
            func PrecompiledPrograms() ([]precompiledseccomp.Program, error)
        programs_to_compile_go_import: Go-style import path to
            `programs_to_compile_go_library`.
        out: Name of the Go source file (with the precompiled seccomp-bpf
            programs embedded in it) to generate. You can add this file as
            source to a `go_library` rule. This will define a package-level
            function:
            GetPrecompiled(programName string) (precompiledseccomp.Program, bool)
        out_package_name: Go package name that `out` belongs to.
        exclude_in_fastbuild: Whether to skip precompilation in fastbuild mode.
            The auto-generated `GetPrecompiled` function will fail all lookups.
        tags: List of tags to pass to the generated genrule.
    """
    if exclude_in_fastbuild:
        native.config_setting(
            name = name + "_fastbuild_cond",
            values = {
                "compilation_mode": "fastbuild",
            },
        )

    # This genrule copies precompiled_lib.tmpl.go to the directory of wherever
    # `precompiled_seccomp_rules` is called.
    # This allows the go:embed directive inside the `.gen.go` file below to
    # work without rewriting the full path.
    native.genrule(
        name = name + "_gen_lib",
        outs = [out + ".gen.lib.tmpl.go"],
        cmd = "cat < $(SRCS) > $@",
        srcs = [
            "//pkg/seccomp/precompiledseccomp:precompiled_lib.tmpl.go",
        ],
    )

    # This genrule generates the Go file of the binary that, when run,
    # precompiles rules and writes them to a designated file.
    gen_cmd_template = (
        "  while IFS= read -r line; do" +
        "    if echo \"$$line\" | grep -q 'REPLACED_IMPORT_THIS_IS_A_LOAD_BEARING_COMMENT'; then" +
        "        {rules_import_echo}" +
        "    elif echo \"$$line\" | grep -q 'PROGRAMS_FUNC_THIS_IS_A_LOAD_BEARING_COMMENT'; then" +
        "        {load_programs_fn_echo}" +
        "    elif echo \"$$line\" | grep -q 'go:embed precompiled_lib.tmpl.go'; then" +
        "        echo -e \"//go:embed " + out + ".gen.lib.tmpl.go\";" +
        "    else" +
        "      echo \"$$line\";" +
        "    fi;" +
        "  done" +
        "  < $(SRCS)" +
        "  > $@"
    )
    gen_cmd = gen_cmd_template.format(
        rules_import_echo = (
            "echo -e \"\\\\trules \\\"" +
            programs_to_compile_go_import +
            "\\\"\";"
        ),
        load_programs_fn_echo = (
            "echo -e \"var loadProgramsFn = rules.PrecompiledPrograms\";"
        ),
    )
    native.genrule(
        name = name + "_gen",
        outs = [out + ".gen.go"],
        cmd = gen_cmd,
        srcs = [
            "//pkg/seccomp/precompiledseccomp:precompile_gen.go",
        ],
    )
    if exclude_in_fastbuild:
        native.genrule(
            name = name + "_gen_stubbed",
            outs = [out + ".gen_stubbed.go"],
            cmd = gen_cmd_template.format(
                rules_import_echo = "true;",
                load_programs_fn_echo = (
                    "echo -e \"var loadProgramsFn func() ([]precompiledseccomp.Program, error) = nil\";"
                ),
            ),
            srcs = [
                "//pkg/seccomp/precompiledseccomp:precompile_gen.go",
            ],
        )

    # This defines the go_binary for the Go file we just generated.
    base_gen_bin_deps = [
        "//pkg/seccomp/precompiledseccomp",
        "//runsc/flag",
    ]
    gen_bin_deps = [programs_to_compile_go_library] + base_gen_bin_deps
    go_binary(
        name = name + "_gen_bin",
        srcs = [out + ".gen.go"],
        deps = gen_bin_deps,
        embedsrcs = [
            ":" + out + ".gen.lib.tmpl.go",
        ],
    )
    if exclude_in_fastbuild:
        go_binary(
            name = name + "_gen_stubbed_bin",
            srcs = [out + ".gen_stubbed.go"],
            deps = base_gen_bin_deps,
            embedsrcs = [
                ":" + out + ".gen.lib.tmpl.go",
            ],
        )

    # Syscall numbers and the audit architecture are compiled into the generator.
    # Run it on the target architecture so its exec-configured Go binary embeds
    # the right constants. Execution constraints cannot be configurable, so each
    # architecture needs its own action; select only the required output below.
    out_cmd = "$(location :" + name + "_gen_bin) --package='" + out_package_name + "' --out=$@"
    for arch, cpu in {
        "amd64": "@platforms//cpu:x86_64",
        "arm64": "@platforms//cpu:aarch64",
    }.items():
        native.genrule(
            name = name + "_compile_" + arch,
            outs = [name + "/" + arch + "/" + out],
            cmd = out_cmd,
            tools = [":" + name + "_gen_bin"],
            exec_compatible_with = ["@platforms//os:linux", cpu],
            tags = tags + ["manual", "requires-mem:16g"],
        )
    native.alias(
        name = name + "_compiled",
        actual = select_arch(
            amd64 = ":" + name + "_compile_amd64",
            arm64 = ":" + name + "_compile_arm64",
        ),
        tags = tags + ["manual"],
    )
    actual = ":" + name + "_compiled"
    if exclude_in_fastbuild:
        # The empty stub is architecture-independent and needs no native worker.
        native.genrule(
            name = name + "_compile_stubbed",
            outs = [name + "/stubbed/" + out],
            cmd = "$(location :" + name + "_gen_stubbed_bin) --package='" + out_package_name + "' --out=$@",
            tools = [":" + name + "_gen_stubbed_bin"],
            tags = tags + ["manual", "requires-mem:16g"],
        )
        actual = select({
            ":" + name + "_fastbuild_cond": ":" + name + "_compile_stubbed",
            "//conditions:default": actual,
        })
    native.alias(name = name, actual = actual, tags = tags + ["requires-mem:16g"])

    # Keep both labels accepted by existing callers, without a copy action.
    native.alias(name = out, actual = ":" + name, tags = tags + ["manual"])
