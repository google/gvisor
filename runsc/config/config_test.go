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

func TestDefault(t *testing.T) {
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(testFlags)
	c, err := NewFromFlags(testFlags)
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

func TestFromFlags(t *testing.T) {
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(testFlags)
	if err := testFlags.Lookup("root").Value.Set("some-path"); err != nil {
		t.Errorf("Flag set: %v", err)
	}
	if err := testFlags.Lookup("debug").Value.Set("true"); err != nil {
		t.Errorf("Flag set: %v", err)
	}
	if err := testFlags.Lookup("num-network-channels").Value.Set("123"); err != nil {
		t.Errorf("Flag set: %v", err)
	}
	if err := testFlags.Lookup("network").Value.Set("none"); err != nil {
		t.Errorf("Flag set: %v", err)
	}

	c, err := NewFromFlags(testFlags)
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
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(testFlags)
	c, err := NewFromFlags(testFlags)
	if err != nil {
		t.Fatal(err)
	}
	c.RootDir = "some-path"
	c.Debug = true
	c.NumNetworkChannels = 123
	c.Network = NetworkNone

	flags := c.ToFlags()
	if len(flags) != 4 {
		t.Errorf("wrong number of flags set, want: 5, got: %d: %s", len(flags), flags)
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
		{
			name:  "host-uds",
			error: "invalid host UDS",
		},
		{
			name:  "host-fifo",
			error: "invalid host fifo",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
			RegisterFlags(testFlags)
			if err := testFlags.Lookup(tc.name).Value.Set("invalid"); err == nil || !strings.Contains(err.Error(), tc.error) {
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
		{
			name: "fsgofer-host-uds+host-uds:open",
			flags: map[string]string{
				"fsgofer-host-uds": "true",
				"host-uds":         "open",
			},
			error: "fsgofer-host-uds has been replaced with host-uds flag",
		},
		{
			name: "fsgofer-host-uds+host-uds:create",
			flags: map[string]string{
				"fsgofer-host-uds": "true",
				"host-uds":         "create",
			},
			error: "fsgofer-host-uds has been replaced with host-uds flag",
		},
		{
			name: "fsgofer-host-uds+host-uds:all",
			flags: map[string]string{
				"fsgofer-host-uds": "true",
				"host-uds":         "all",
			},
			error: "fsgofer-host-uds has been replaced with host-uds flag",
		},
		{
			name: "overlay+overlay2:root",
			flags: map[string]string{
				"overlay":  "true",
				"overlay2": "root:memory",
			},
			error: "overlay flag has been replaced with overlay2 flag",
		},
		{
			name: "overlay+overlay2:all",
			flags: map[string]string{
				"overlay":  "true",
				"overlay2": "all:memory",
			},
			error: "overlay flag has been replaced with overlay2 flag",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
			RegisterFlags(testFlags)
			for name, val := range tc.flags {
				if err := testFlags.Lookup(name).Value.Set(val); err != nil {
					t.Errorf("%s=%q: %v", name, val, err)
				}
			}
			if _, err := NewFromFlags(testFlags); err == nil || !strings.Contains(err.Error(), tc.error) {
				t.Errorf("NewFromFlags() wrong error reported: %v", err)
			}
		})
	}
}

func TestOverride(t *testing.T) {
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(testFlags)
	c, err := NewFromFlags(testFlags)
	if err != nil {
		t.Fatal(err)
	}
	c.AllowFlagOverride = true

	t.Run("string", func(t *testing.T) {
		c.RootDir = "foobar"
		if err := c.Override(testFlags, "root", "bar"); err != nil {
			t.Fatalf("Override(root, bar) failed: %v", err)
		}
		if c.RootDir != "bar" {
			t.Errorf("Override(root, bar) didn't work: %+v", c)
		}
	})

	t.Run("bool", func(t *testing.T) {
		c.Debug = true
		if err := c.Override(testFlags, "debug", "false"); err != nil {
			t.Fatalf("Override(debug, false) failed: %v", err)
		}
		if c.Debug {
			t.Errorf("Override(debug, false) didn't work: %+v", c)
		}
	})

	t.Run("enum", func(t *testing.T) {
		c.FileAccess = FileAccessShared
		if err := c.Override(testFlags, "file-access", "exclusive"); err != nil {
			t.Fatalf("Override(file-access, exclusive) failed: %v", err)
		}
		if c.FileAccess != FileAccessExclusive {
			t.Errorf("Override(file-access, exclusive) didn't work: %+v", c)
		}
	})
}

func TestOverrideDisabled(t *testing.T) {
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(testFlags)
	c, err := NewFromFlags(testFlags)
	if err != nil {
		t.Fatal(err)
	}
	const errMsg = "flag override disabled"
	if err := c.Override(testFlags, "root", "path"); err == nil || !strings.Contains(err.Error(), errMsg) {
		t.Errorf("Override() wrong error: %v", err)
	}
}

func TestOverrideError(t *testing.T) {
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(testFlags)
	c, err := NewFromFlags(testFlags)
	if err != nil {
		t.Fatal(err)
	}
	c.AllowFlagOverride = true
	for _, tc := range []struct {
		name  string
		value string
		error string
	}{
		{
			name:  "invalid",
			value: "valid",
			error: `flag "invalid" not found`,
		},
		{
			name:  "debug",
			value: "invalid",
			error: "error setting flag debug",
		},
		{
			name:  "file-access",
			value: "invalid",
			error: "invalid file access type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Override(testFlags, tc.name, tc.value); err == nil || !strings.Contains(err.Error(), tc.error) {
				t.Errorf("Override(%q, %q) wrong error: %v", tc.name, tc.value, err)
			}
		})
	}
}

func TestOverrideAllowlist(t *testing.T) {
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(testFlags)
	c, err := NewFromFlags(testFlags)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		flag  string
		value string
		error string
	}{
		{
			flag:  "debug",
			value: "true",
		},
		{
			flag:  "debug",
			value: "123",
			error: "error setting flag",
		},
		{
			flag:  "oci-seccomp",
			value: "true",
		},
		{
			flag:  "oci-seccomp",
			value: "false",
			error: `disabling "oci-seccomp" requires flag`,
		},
		{
			flag:  "oci-seccomp",
			value: "123",
			error: "invalid syntax",
		},
		{
			flag:  "profile",
			value: "true",
			error: "flag override disabled",
		},
		{
			flag:  "profile",
			value: "123",
			error: "flag override disabled",
		},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			err := c.Override(testFlags, tc.flag, tc.value)
			if len(tc.error) == 0 {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.error) {
				t.Errorf("Override(%q, %q) wrong error: %v", tc.flag, tc.value, err)
			}
		})
	}
}
