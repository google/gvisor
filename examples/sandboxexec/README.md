# gVisor SandboxExec Examples

This directory provides clear, end-to-end examples demonstrating how to use
**gVisor SandboxExec** language bindings to build secure, programmable
sandboxes.

--------------------------------------------------------------------------------

## What is gVisor?

[gVisor](https://gvisor.dev) is an application kernel that provides strong
workload isolation by intercepting application system calls in user space. Its
`runsc` runtime provides a secure sandbox boundary between untrusted code and
the host Linux kernel.

--------------------------------------------------------------------------------

## What is SandboxExec?

**SandboxExec** language bindings (available in Python, Go, and more) give
developers a direct, programmatic API to spawn and manage lightweight gVisor
sandboxes on demand. With SandboxExec, you can:

1.  Create and tear down sandboxes programmatically using language-native
    constructs (e.g., Python `with` statements).
2.  Configure fine-grained filesystem isolation (read-only input mounts,
    writable output directories, and memory-backed scratch spaces).
3.  Enforce strict network isolation (`none`, `host`, or `sandbox`) using the
    `NetworkMode` enum.
4.  Execute commands with custom working directories, environment variables, and
    per-command execution timeouts.

--------------------------------------------------------------------------------

## Examples Catalog

Each subfolder contains a standalone, well-documented example for a specific
language binding:

| Language           | Directory            | Description                     |
| :----------------- | :------------------- | :------------------------------ |
| **Python**         | [`python/`](python/) | Safe code runner CLI            |
:                    :                      : demonstrating mounts, timeouts, :
:                    :                      : and network isolation.          :
| **Go** *(Planned)* | `go/`                | Go bindings reference           |
:                    :                      : implementation.                 :

--------------------------------------------------------------------------------

## Getting Started

Check out the language-specific folder (e.g., [`python/`](python/)) for detailed
installation instructions, prerequisites, and runnable examples.
