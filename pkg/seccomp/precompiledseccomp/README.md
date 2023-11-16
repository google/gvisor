# precompiledseccomp

This package provides build tooling to embed precompiled seccomp-bpf programs
inside Go binaries. Within gVisor, this is useful to keep startup time fast.

It also features basic support for runtime-modifiable `uint32` variables within
embedded programs. This allows having values that are only known at runtime
(e.g. FD numbers) to remain usable within seccomp filtering rules.

## Usage

You will need two Go libraries: One where you'll list the seccomp-bpf programs
that you want embedded, and one where those precompiled programs will be
embedded. This allows you to define the list of seccomp-bpf programs
programmatically.

### 1: Define a Go library returning a set of programs to precompile

You need to define a `go_library` target which declares a package-level
function:

```go
func PrecompiledPrograms() ([]precompiledseccomp.Program, error)
```

Look at [example.go](example/example.go) for a documented example.

### 2: Call `precompiled_seccomp_rules`

The [`precompiled_seccomp_rules`](defs.bzl) BUILD macro will auto-generate a
`.go` file which contains the precompiled seccomp-bpf binary that your first Go
library specifies.

Look at [example/usage/BUILD](example/usage/BUILD) for an example.

### 3: Use the generated library to access embedded programs

Use the auto-generated `.go` file from step 2 in the second `go_library`. A new
package-level function will be defined:

```go
func GetPrecompiled(programName string) (precompiledseccomp.Program, bool)
```

You can call it to get the precompiled seccomp-bpf program.

See [example/usage/usage.go](example/usage/usage.go) for a documented example.

## How does it work?

See the [`precompiled_seccomp_rules`](defs.bzl) BUILD macro for the precise
logic. At a high level, it generates a `go_binary` target that imports your
first `go_library` (expressing your desired seccomp-bpf program). When this Go
binary runs, it will compile the programs and output Go code that contains the
compiled programs. Lastly, we use a `genrule` to execute this generated program
and direct its output to a file of your choosing, which you can now embed in
your second `go_library`.

In order to support variables, the compilation step actually compiles the
program twice, using different placeholder values for all variables. It looks at
the places in the BPF bytecode where these values show up, and ensures that
these offsets are consistent across both compilation attempts.
