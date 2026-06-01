// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build loong64
// +build loong64

// Package kvm: the LoongArch port does NOT implement the KVM platform.
// The Loongson 3A5000 supports the LVZ extension, but mainline Linux
// LoongArch KVM support is too recent for a reliable demo on Kylin V11.
// This file provides a package-level placeholder so that
// pkg/sentry/platform/platforms can still import the package via the
// blank `_` import idiom; the platform itself simply does not register
// with platform.Register on LoongArch64.

package kvm

// init does nothing on LoongArch64 — KVM is not registered.
func init() {}

// machine type exists solely so the generated atomicptr_machine_unsafe.go
// (a go_template_instance over the kvm.machine type) compiles. The KVM
// platform itself is not registered on LoongArch.
type machine struct{}
