"""Macro for precompiling seccomp-bpf programs."""

load("//tools:defs.bzl", "expand_template", "go_binary", "select_arch", "target_emulator")

def _run_generator_impl(ctx):
    generator = ctx.attr.exec_generator or ctx.attr.generator
    executable = generator[DefaultInfo].files_to_run
    tools = []
    arguments = []
    qemu = None
    toolchain = None
    if not ctx.attr.exec_generator:
        if ctx.attr.qemu:
            qemu = ctx.attr.qemu[DefaultInfo].files_to_run
        elif target_emulator.toolchain_type:
            qemu_info = ctx.toolchains[target_emulator.toolchain_type]
            if qemu_info:
                qemu = qemu_info.qemu
                toolchain = target_emulator.toolchain_type
    if qemu:
        arguments.extend(ctx.attr.qemu_args)
        tools.append(executable)
        arguments.append(executable.executable.path)
        executable = qemu
    arguments.extend([
        "--package=" + ctx.attr.out_package_name,
        "--out=" + ctx.outputs.out.path,
    ])
    ctx.actions.run(
        executable = executable,
        outputs = [ctx.outputs.out],
        tools = tools,
        arguments = arguments,
        mnemonic = "PrecompileSeccomp",
        toolchain = toolchain,
    )
    return [DefaultInfo(files = depset([ctx.outputs.out]))]

_run_generator = rule(
    implementation = _run_generator_impl,
    attrs = {
        "generator": attr.label(executable = True, cfg = "target"),
        "exec_generator": attr.label(executable = True, cfg = "exec"),
        "out": attr.output(mandatory = True),
        "out_package_name": attr.string(mandatory = True),
        "qemu": attr.label(executable = True, cfg = "exec"),
        "qemu_args": attr.string_list(),
    },
    toolchains = target_emulator.toolchains,
)

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
        name: Name of the generated target.
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
        tags: List of tags to pass to the generated action.
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

    # Compile the real generator for the target platform and the stub for the
    # execution platform. The action resolves QEMU for this target/exec pair.
    generator = ":" + name + "_gen_bin"
    exec_generator = None
    if exclude_in_fastbuild:
        generator = select({
            ":" + name + "_fastbuild_cond": None,
            "//conditions:default": generator,
        })
        exec_generator = select({
            ":" + name + "_fastbuild_cond": ":" + name + "_gen_stubbed_bin",
            "//conditions:default": None,
        })
    _run_generator(
        name = name,
        generator = generator,
        exec_generator = exec_generator,
        out = out,
        out_package_name = out_package_name,
        qemu = target_emulator.binary,
        qemu_args = select_arch(arm64 = ["-cpu", "neoverse-n1"], default = []),
        tags = tags + ["requires-mem:16g"],
    )
