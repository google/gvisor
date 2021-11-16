// Copyright 2021 The gVisor Authors.
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

// Package gvunix supports syscalls to different host platforms (e.g. Linux and
// Darwin). Some syscalls are provided by golang.org/x/sys/unix, are
// platform-independent, and do not need to be implemented here.
// TODO: Rename this to Darwin. The Darwin syscalls will live here and the
// Linux syscalls just live at their call sites.
package gvunix
