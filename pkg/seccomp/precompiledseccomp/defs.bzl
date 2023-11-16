"""Macro for precompiling seccomp-bpf programs."""

load("//tools:defs.bzl", "go_binary")

def precompiled_seccomp_rules(
        name,
        programs_to_compile_go_library,
        programs_to_compile_go_import,
        out,
        out_package_name):
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
    """

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
    native.genrule(
        name = name + "_gen",
        outs = [out + ".gen.go"],
        cmd = (
            "  while IFS= read -r line; do" +
            "    if echo \"$$line\" | grep -q 'REPLACED_IMPORT_THIS_IS_A_LOAD_BEARING_COMMENT'; then" +
            "        echo -e \"\\\\trules \\\"" + programs_to_compile_go_import + "\\\"\";" +
            "    elif echo \"$$line\" | grep -q 'PROGRAMS_FUNC_THIS_IS_A_LOAD_BEARING_COMMENT'; then" +
            "        echo -e \"var loadProgramsFn = rules.PrecompiledPrograms\";" +
            "    elif echo \"$$line\" | grep -q 'go:embed precompiled_lib.tmpl.go'; then" +
            "        echo -e \"//go:embed " + out + ".gen.lib.tmpl.go\";" +
            "    else" +
            "      echo \"$$line\";" +
            "    fi;" +
            "  done" +
            "  < $(SRCS)" +
            "  > $@"
        ),
        srcs = [
            "//pkg/seccomp/precompiledseccomp:precompile_gen.go",
        ],
    )

    # This defines the go_binary for the Go file we just generated.
    go_binary(
        name = name + "_gen_bin",
        srcs = [out + ".gen.go"],
        deps = [
            programs_to_compile_go_library,
            "//runsc/flag",
        ],
        embedsrcs = [
            ":" + out + ".gen.lib.tmpl.go",
        ],
    )

    # This genrule actually runs the go_binary we just declared, and writes
    # its output (containing the precompiled rules) to the desired `out` file.
    native.genrule(
        name = name,
        outs = [out],
        cmd = (
            "$(location :" + name + "_gen_bin) --package='" + out_package_name + "' --out=$@"
        ),
        tools = [":" + name + "_gen_bin"],
    )
