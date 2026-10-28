"""Macro for precompiling seccomp-bpf programs."""

load("//tools:defs.bzl", "expand_template", "go_binary", "select_arch", "target_emulator")

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
        name: Name of the final genrule.
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

    template = "//pkg/seccomp/precompiledseccomp:load_programs.go.in"
    expand_template(
        name = name + "_gen",
        out = out + ".gen.go",
        substitutions = {
            "{RULES_IMPORT}": 'rules "{}"'.format(programs_to_compile_go_import),
            "{LOAD_PROGRAMS}": "rules.PrecompiledPrograms",
        },
        template = template,
    )
    if exclude_in_fastbuild:
        expand_template(
            name = name + "_gen_stubbed",
            out = out + ".gen_stubbed.go",
            substitutions = {
                "{RULES_IMPORT}": "",
                "{LOAD_PROGRAMS}": "nil",
            },
            template = template,
        )

    generator = "//pkg/seccomp/precompiledseccomp:precompile_gen.go"
    embedsrcs = ["//pkg/seccomp/precompiledseccomp:precompiled_lib.tmpl.go"]
    base_gen_bin_deps = [
        "//pkg/seccomp/precompiledseccomp",
        "//runsc/flag",
    ]
    gen_bin_deps = [programs_to_compile_go_library] + base_gen_bin_deps
    go_binary(
        name = name + "_gen_dynamic_bin",
        srcs = [generator, out + ".gen.go"],
        deps = gen_bin_deps,
        embedsrcs = embedsrcs,
        pure = True,
        noasan = True,
        race = "off",
    )

    # gotsan forces the generator to be dynamically linked.
    # QEMU cannot load the dynamic loader of the generator,
    # so it must be static in this configuration.
    go_binary(
        name = name + "_gen_static_bin",
        srcs = [generator, out + ".gen.go"],
        deps = gen_bin_deps,
        embedsrcs = embedsrcs,
        pure = True,
        static = True,
        noasan = True,
        race = "off",
        nogo = False,
        tags = ["manual"],
    )
    native.alias(
        name = name + "_gen_bin",
        actual = select({
            "//tools:gotsan": ":" + name + "_gen_static_bin",
            "//conditions:default": ":" + name + "_gen_dynamic_bin",
        }),
    )
    if exclude_in_fastbuild:
        go_binary(
            name = name + "_gen_stubbed_bin",
            srcs = [generator, out + ".gen_stubbed.go"],
            deps = base_gen_bin_deps,
            embedsrcs = embedsrcs,
        )

    # This genrule actually runs the go_binary we just declared, and writes
    # its output (containing the precompiled rules) to the desired `out` file.
    #
    # The generator is a source (rather than a tool) of this genrule, so that
    # it is built for the target platform rather than for the execution
    # platform. If the execution platform's architecture differs from the
    # target's (i.e. when cross-compiling), it is run under a user-mode
    # emulator. If no emulator is configured for the target architecture, it
    # is run directly, which works if the kernel is configured to run foreign
    # binaries (binfmt_misc) and fails otherwise.
    #
    # Execution platform constraints are deliberately not used here: they would
    # make cross-architecture configurations fail analysis wherever no
    # execution platform for the target architecture is available.
    emulator = target_emulator()
    out_args = " --package='" + out_package_name + "' --out=$@"
    run_gen_cmd = (
        "GEN=$(location :" + name + "_gen_bin); " +
        "RUN=; " +
        "if [ -n \"$$TARGET_ARCH\" ] && [ \"$$(uname -m)\" != \"$$TARGET_ARCH\" ]; then " +
        "  RUN=\"$$EMULATOR\"; " +
        "fi; " +
        "$$RUN \"$$GEN\"" + out_args + " || { " +
        "  echo \"Failed to run $$GEN (built for $$TARGET_ARCH) on $$(uname -m)" +
        " (emulator: $${RUN:-none}).\" >&2; " +
        "  exit 1; " +
        "}"
    )
    run_gen_env = (
        "TARGET_ARCH=" + select_arch(
            amd64 = "x86_64",
            arm64 = "aarch64",
            riscv64 = "riscv64",
            default = "",
        ) + "; " +
        "EMULATOR='" + emulator.cmd + "'; "
    )
    if exclude_in_fastbuild:
        native.genrule(
            name = name,
            outs = [out],
            srcs = select({
                ":" + name + "_fastbuild_cond": [],
                "//conditions:default": [":" + name + "_gen_bin"],
            }),
            # The stubbed generator's output does not depend on the
            # architecture, so it is built for the execution platform.
            cmd = run_gen_env + select({
                ":" + name + "_fastbuild_cond": "$(location :" + name + "_gen_stubbed_bin)" + out_args,
                "//conditions:default": run_gen_cmd,
            }),
            tools = select({
                ":" + name + "_fastbuild_cond": [":" + name + "_gen_stubbed_bin"],
                "//conditions:default": [],
            }) + emulator.tools,
            tags = tags + ["requires-mem:16g"],
        )
    else:
        native.genrule(
            name = name,
            outs = [out],
            srcs = [":" + name + "_gen_bin"],
            cmd = run_gen_env + run_gen_cmd,
            tools = emulator.tools,
            tags = tags + ["requires-mem:16g"],
        )
