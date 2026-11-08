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

package cmd

import (
	"testing"

	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// subpageBlocksCmd is a command with a --save-subpage-blocks flag.
type subpageBlocksCmd struct {
	name     string
	setFlags func(*flag.FlagSet)
	policy   func() *config.SubpageBlocksPolicy
}

// newSubpageBlocksCmds returns new checkpoint and fscheckpoint commands.
func newSubpageBlocksCmds() []subpageBlocksCmd {
	cp, fc := &Checkpoint{}, &FSCheckpoint{}
	return []subpageBlocksCmd{
		{"checkpoint", cp.SetFlags, cp.saveSubpageBlocks.ptr},
		{"fscheckpoint", fc.SetFlags, fc.saveSubpageBlocks.ptr},
	}
}

// TestSaveSubpageBlocksFlag checks that the checkpoint and fscheckpoint
// commands accept --save-subpage-blocks, and pass it on only if it is given.
func TestSaveSubpageBlocksFlag(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		want    *config.SubpageBlocksPolicy
		wantErr bool
	}{
		{args: nil, want: nil},
		{args: []string{"--save-subpage-blocks=4k"}, want: policyPtr(config.SubpageBlocks4K)},
		{args: []string{"--save-subpage-blocks=none"}, want: policyPtr(config.SubpageBlocksNone)},
		{args: []string{"--save-subpage-blocks=2k"}, wantErr: true},
	} {
		for _, cmd := range newSubpageBlocksCmds() {
			f := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
			cmd.setFlags(f)
			err := f.Parse(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Errorf("%s %v parsed, want error", cmd.name, tc.args)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s %v: %v", cmd.name, tc.args, err)
				continue
			}
			got := cmd.policy()
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Errorf("%s %v: policy = %v, want %v", cmd.name, tc.args, got, tc.want)
			}
		}
	}
}

func policyPtr(p config.SubpageBlocksPolicy) *config.SubpageBlocksPolicy {
	return &p
}
