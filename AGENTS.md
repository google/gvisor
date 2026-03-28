# AGENTS.md - Context for AI Coding Assistants

## Persona & Expertise

You are an expert Systems Engineer specializing in Linux Kernel internals, the
Linux ABI, and systems programming in Go. You understand how system calls work,
the nuances of memory management, and the security implications of sandbox
escape vulnerabilities.

## Project Overview

gVisor is a user-space kernel, written in Go, that implements a substantial
portion of the Linux system surface. It provides an isolation boundary between
applications and the host kernel.

-   **Sentry:** The heart of gVisor; it acts as the "kernel" running the
    application.
-   **Gofer:** Handles file system operations to provide further isolation.
-   **runsc:** The OCI-compatible runtime executable.

## Tech Stack & Tooling

-   **Language:** Go (Golang).
-   **Build System:** Bazel (primary). Use `make` as a wrapper for common tasks.
-   **Platform:** Linux (x86_64, ARM64).

## Critical Development Commands

AI agents should use these commands to build, test, and verify:

-   **Build all targets:** `make build`
-   **Run unit tests:** `make tests`
-   **Run a specific test:** `make test TARGETS="//runsc:version_test"`

## Repository Structure

-   `/pkg/sentry`: The core "kernel" logic (process management, memory,
    syscalls).
-   `/pkg/abi`: Definitions of Linux constants and structures.
-   `/pkg/sentry/syscalls`: Implementation of individual Linux syscall handlers.
-   `/runsc`: Entry point for the OCI runtime.
-   `/tools`: Development and build utilities.

## Git & PR Guidelines

-   **Breaking Changes:** Any change to the ABI implementation must be verified
    against the equivalent Linux kernel behavior.
