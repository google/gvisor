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

package cli

import (
	"reflect"
	"testing"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

var fakeFlagValues = [...]string{
	"1",
	"2:2",
	"foo",
	"none",
	"1,2,3",
	"2h45m",
	"1:1,2:2",
	"0 0 1,100000 100000 65536",
}

func dupFlag(t *testing.T, cmd subcommands.Command, flagName string) *flag.Flag {
	// To create a true duplicate of the flag, we need to duplicate the command
	// and its FlagSet.
	var cmd2 subcommands.Command
	var fs2 flag.FlagSet
	cmd2 = reflect.New(reflect.TypeOf(cmd).Elem()).Interface().(subcommands.Command)
	cmd2.SetFlags(&fs2)
	flag2 := fs2.Lookup(flagName)
	if flag2 == nil {
		t.Fatalf("duplicate FlagSet does not contain flag %q for cmd %q", flagName, cmd.Name())
	}
	return flag2
}

// Tests that all the flags in all commands are idempotent; i.e. Set(String())
// should be an idempotent operation.
func TestFlagSetIdempotent(t *testing.T) {
	cmds := make(map[string][]subcommands.Command)
	forEachCmd(func(cmd subcommands.Command, group string) {
		if cmdList, ok := cmds[group]; ok {
			cmds[group] = append(cmdList, cmd)
		} else {
			cmds[group] = []subcommands.Command{cmd}
		}
	})

	for group, cmdList := range cmds {
		t.Run(group, func(t *testing.T) {
			for _, cmd := range cmdList {
				t.Run(cmd.Name(), func(t *testing.T) {
					var fs flag.FlagSet
					cmd.SetFlags(&fs)

					// Iterate through all flags configured by this command.
					fs.VisitAll(func(flag *flag.Flag) {
						// Try a list of possible values for this flag.
						matchedOneFlag := false
						for _, v := range fakeFlagValues {
							// Set() may have side effects even when it fails. So create a new
							// flag for each try.
							curFlag := dupFlag(t, cmd, flag.Name)
							if err := curFlag.Value.Set(v); err != nil {
								continue
							}
							// Worked. Now test that this flag is idempotent.
							oldValue := curFlag.Value.String()
							// Get a fresh flag.Flag to Set() this old value on.
							newFlag := dupFlag(t, cmd, flag.Name)
							if err := newFlag.Value.Set(oldValue); err != nil {
								t.Errorf("flag %q from cmd %q is not idempotent: oldValue = %q, err = %v", flag.Name, cmd.Name(), oldValue, err)
								return
							}
							// Compare this new flag value with old value.
							if newValue := newFlag.Value.String(); newValue != oldValue {
								t.Errorf("flag %q from cmd %q is not idempotent: oldValue = %q, newValue = %q", flag.Name, cmd.Name(), oldValue, newValue)
								return
							}
							matchedOneFlag = true
						}
						if !matchedOneFlag {
							t.Fatalf("none of the fake flag values work for flag %q from cmd %q", flag.Name, cmd.Name())
						}
					})
				})
			}
		})
	}
}
