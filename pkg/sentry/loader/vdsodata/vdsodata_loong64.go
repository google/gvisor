//go:build loong64
// +build loong64

package vdsodata

import _ "embed"

// Binary is a minimal compiled LoongArch64 vDSO. The exported symbols
// (__kernel_rt_sigreturn etc.) are placeholder stubs that just return -1;
// runsc on LoongArch falls back to direct syscalls so the binary is never
// actually executed, but it must be a parseable ELF for the sentry's
// vdso.PrepareVDSO() loader.
//
//go:embed vdso_loong64_stub.so
var Binary []byte
