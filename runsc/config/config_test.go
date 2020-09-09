// Copyright 2020 The gVisor Authors.
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

package config

import (
	"strings"
	"testing"

	"gvisor.dev/gvisor/runsc/flag"
)

func init() {
	RegisterFlags()
}

func TestDefault(t *testing.T) {
	c, err := NewFromFlags()
	if err != nil {
		t.Fatal(err)
	}
	// "--root" is always set to something different than the default. Reset it
	// to make it easier to test that default values do not generate flags.
	c.RootDir = ""

	// All defaults doesn't require setting flags.
	flags := c.ToFlags()
	if len(flags) > 0 {
		t.Errorf("default flags not set correctly for: %s", flags)
	}
}

func setDefault(name string) {
	fl := flag.CommandLine.Lookup(name)
	fl.Value.Set(fl.DefValue)
}

func TestFromFlags(t *testing.T) {
	flag.CommandLine.Lookup("root").Value.Set("some-path")
	flag.CommandLine.Lookup("debug").Value.Set("true")
	flag.CommandLine.Lookup("num-network-channels").Value.Set("123")
	flag.CommandLine.Lookup("network").Value.Set("none")
	defer func() {
		setDefault("root")
		setDefault("debug")
		setDefault("num-network-channels")
		setDefault("network")
	}()

	c, err := NewFromFlags()
	if err != nil {
		t.Fatal(err)
	}
	if want := "some-path"; c.RootDir != want {
		t.Errorf("RootDir=%v, want: %v", c.RootDir, want)
	}
	if want := true; c.Debug != want {
		t.Errorf("Debug=%v, want: %v", c.Debug, want)
	}
	if want := 123; c.NumNetworkChannels != want {
		t.Errorf("NumNetworkChannels=%v, want: %v", c.NumNetworkChannels, want)
	}
	if want := NetworkNone; c.Network != want {
		t.Errorf("Network=%v, want: %v", c.Network, want)
	}
}

func TestToFlags(t *testing.T) {
	c, err := NewFromFlags()
	if err != nil {
		t.Fatal(err)
	}
	c.RootDir = "some-path"
	c.Debug = true
	c.NumNetworkChannels = 123
	c.Network = NetworkNone

	flags := c.ToFlags()
	if len(flags) != 4 {
		t.Errorf("wrong number of flags set, want: 4, got: %d: %s", len(flags), flags)
	}
	t.Logf("Flags: %s", flags)
	fm := map[string]string{}
	for _, f := range flags {
		kv := strings.Split(f, "=")
		fm[kv[0]] = kv[1]
	}
	for name, want := range map[string]string{
		"--root":                 "some-path",
		"--debug":                "true",
		"--num-network-channels": "123",
		"--network":              "none",
	} {
		if got, ok := fm[name]; ok {
			if got != want {
				t.Errorf("flag %q, want: %q, got: %q", name, want, got)
			}
		} else {
			t.Errorf("flag %q not set", name)
		}
	}
}

// TestInvalidFlags checks that enum flags fail when value is not in enum set.
func TestInvalidFlags(t *testing.T) {
	for _, tc := range []struct {
		name  string
		error string
	}{
		{
			name:  "file-access",
			error: "invalid file access type",
		},
		{
			name:  "network",
			error: "invalid network type",
		},
		{
			name:  "qdisc",
			error: "invalid qdisc",
		},
		{
			name:  "watchdog-action",
			error: "invalid watchdog action",
		},
		{
			name:  "ref-leak-mode",
			error: "invalid ref leak mode",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer setDefault(tc.name)
			if err := flag.CommandLine.Lookup(tc.name).Value.Set("invalid"); err == nil || !strings.Contains(err.Error(), tc.error) {
				t.Errorf("flag.Value.Set(invalid) wrong error reported: %v", err)
			}
		})
	}
}

func TestValidationFail(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags map[string]string
		error string
	}{
		{
			name: "shared+overlay",
			flags: map[string]string{
				"file-access": "shared",
				"overlay":     "true",
			},
			error: "overlay flag is incompatible",
		},
		{
			name: "network-channels",
			flags: map[string]string{
				"num-network-channels": "-1",
			},
			error: "num_network_channels must be > 0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, val := range tc.flags {
				defer setDefault(name)
				if err := flag.CommandLine.Lookup(name).Value.Set(val); err != nil {
					t.Errorf("%s=%q: %v", name, val, err)
				}
			}
			if _, err := NewFromFlags(); err == nil || !strings.Contains(err.Error(), tc.error) {
				t.Errorf("NewFromFlags() wrong error reported: %v", err)
			}
		})
	}
}
