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

// Package systrap: the LoongArch port does NOT implement the systrap
// platform (we ship only ptrace). This file is the package-level
// placeholder that lets the package compile under loong64 so blank
// imports from platforms keep working.

package systrap

// init does nothing on LoongArch64 — systrap is not registered.
func init() {}

// sharedContext / subprocess type stubs are referenced by the
// generated context_list.go and subprocess_refs.go templates.
type sharedContext struct {
	contextEntry

}

type subprocess struct{}


// Methods required by the generic intrusive list template.
