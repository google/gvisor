// Copyright 2023 The gVisor Authors.
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

package sysmsg

import (
	_ "embed"
)

// SighandlerBlob contains the compiled code of the sysmsg signal handler.
//
//go:embed sighandler.built-in.arm64.bin
var SighandlerBlob []byte

// ArchState defines variables specific to the architecture being
// used.
type ArchState struct{}

// Init initializes the arch specific state.
func (s *ArchState) Init() {}

func (s *ArchState) String() string { return "sysmsg.ArchState{}" }
