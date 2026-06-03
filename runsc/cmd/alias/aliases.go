// Copyright 2026 The gVisor Authors.
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

// Package alias provides aliases for runsc commands.
package alias

import (
	"os"
	"path/filepath"

	"gvisor.dev/gvisor/runsc/cmd/alias/bwrap"
	"gvisor.dev/gvisor/runsc/cmd/util"
)

// aliasType represents the type of alias.
type aliasType string

const (
	aliasBwrap  aliasType = "bwrap"
	aliasNsjail aliasType = "nsjail"
)

// HandleAlias routes the command to the appropriate alias handler.
func HandleAlias() {
	base := filepath.Base(os.Args[0])
	switch aliasType(base) {
	case aliasBwrap:
		os.Args = append([]string{os.Args[0], string(aliasBwrap)}, os.Args[1:]...)
		return
	case aliasNsjail:
		panic("Nsjail alias not implemented")
	}
}

// Commands returns the map of `alias` subcommands.
func Commands() map[util.SubCommand]string {
	return map[util.SubCommand]string{
		new(bwrap.Cli): "",
	}
}
