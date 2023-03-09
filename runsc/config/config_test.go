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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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

func TestToFlagsFromFlags(t *testing.T) {
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(testFlags)
	testFlags.Set("root", "some-path")
	testFlags.Set("debug", "true")
	testFlags.Set("profile", "false") // Matches default value.
	testFlags.Set("num-network-channels", "123")
	testFlags.Set("network", "none")
	c, err := NewFromFlags(testFlags)
	if err != nil {
		t.Fatal(err)
	}

	flags := c.ToFlags()
	if len(flags) != 5 {
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
		"--profile":              "false",
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

func TestToFlagsFromManual(t *testing.T) {
	c := &Config{
		RootDir:            "some-path",
		Debug:              true,
		ProfileEnable:      false, // Matches default flag value.
		NumNetworkChannels: 123,
		Network:            NetworkNone,
	}

	// Create a second config with flag-default values that we'll copy from.
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(testFlags)
	cfgDefault, err := NewFromFlags(testFlags)
	if err != nil {
		t.Fatal(err)
	}

	// Set all the unset fields of c to their flag-default value from cfgDefault.
	cfgReflect := reflect.ValueOf(c).Elem()
	cfgDefaultReflect := reflect.ValueOf(cfgDefault).Elem()
	cfgType := cfgReflect.Type()
	for i := 0; i < cfgType.NumField(); i++ {
		f := cfgType.Field(i)
		name, ok := f.Tag.Lookup("flag")
		if !ok {
			// No flag set for this field.
			continue
		}
		if name == "root" || name == "debug" || name == "profile" || name == "num-network-channels" || name == "network" {
			continue
		}
		cfgReflect.Field(i).Set(cfgDefaultReflect.Field(i))
	}

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
	if _, hasProfile := fm["--profile"]; hasProfile {
		t.Error("--profile flag unexpectedly set")
	}
}

// TestInvalidFlags checks that enum flags fail when value is not in enum set.
func TestInvalidFlags(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		error string
	}{
		{
			name:  "file-access",
			value: "invalid",
			error: "invalid file access type",
		},
		{
			name:  "network",
			value: "invalid",
			error: "invalid network type",
		},
		{
			name:  "qdisc",
			value: "invalid",
			error: "invalid qdisc",
		},
		{
			name:  "watchdog-action",
			value: "invalid",
			error: "invalid watchdog action",
		},
		{
			name:  "ref-leak-mode",
			value: "invalid",
			error: "invalid ref leak mode",
		},
		{
			name:  "host-uds",
			value: "invalid",
			error: "invalid host UDS",
		},
		{
			name:  "host-fifo",
			value: "invalid",
			error: "invalid host fifo",
		},
		{
			name:  "overlay2",
			value: "root:/tmp",
			error: "unexpected medium specifier for --overlay2: \"/tmp\"",
		},
		{
			name:  "overlay2",
			value: "root:dir=tmp",
			error: "overlay host file directory should be an absolute path, got \"tmp\"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
			RegisterFlags(testFlags)
			if err := testFlags.Lookup(tc.name).Value.Set(tc.value); err == nil || !strings.Contains(err.Error(), tc.error) {
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
				"overlay2":    "root:self",
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
		if err := c.Override(testFlags, "root", "bar", false); err != nil {
			t.Fatalf("Override(root, bar) failed: %v", err)
		}
		if c.RootDir != "bar" {
			t.Errorf("Override(root, bar) didn't work: %+v", c)
		}
	})

	t.Run("bool", func(t *testing.T) {
		c.Debug = true
		if err := c.Override(testFlags, "debug", "false", false); err != nil {
			t.Fatalf("Override(debug, false) failed: %v", err)
		}
		if c.Debug {
			t.Errorf("Override(debug, false) didn't work: %+v", c)
		}
	})

	t.Run("enum", func(t *testing.T) {
		c.FileAccess = FileAccessShared
		if err := c.Override(testFlags, "file-access", "exclusive", false); err != nil {
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
	if err := c.Override(testFlags, "root", "path", false); err == nil || !strings.Contains(err.Error(), errMsg) {
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
			if err := c.Override(testFlags, tc.name, tc.value, false); err == nil || !strings.Contains(err.Error(), tc.error) {
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
		force bool
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
			value: "true",
			force: true,
		},
		{
			flag:  "profile",
			value: "123",
			error: "flag override disabled",
		},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			err := c.Override(testFlags, tc.flag, tc.value, tc.force)
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

func TestBundles(t *testing.T) {
	noChange := func(t *testing.T, old, new *Config) {
		t.Helper()
		if diff := cmp.Diff(old, new, cmp.AllowUnexported(Config{})); diff != "" {
			t.Errorf("different configs:\n%+v\nvs\n%+v\nDiff:\n%s", old, new, diff)
		}
	}
	for _, test := range []struct {
		// Name of the test.
		Name string

		// List of bundles that exist for the purpose of this test.
		BundleConfig map[BundleName]Bundle

		// Command-line arguments passed as explicit flags.
		CommandLine []string

		// Names of the bundles to apply.
		Bundles []BundleName

		// Whether we expect applying bundles to fail.
		WantErr bool

		// If bundles were successfully applied, this function is called to compare
		// pre-bundle-application and post-bundle-application configs.
		Verify func(t *testing.T, old, new *Config)
	}{
		{
			Name:         "empty bundle",
			BundleConfig: map[BundleName]Bundle{"empty": {}},
			Bundles:      []BundleName{"empty"},
			Verify:       noChange,
		},
		{
			Name: "no-op bundle",
			BundleConfig: map[BundleName]Bundle{
				"no-debug": {
					"debug": "false",
				},
			},
			Bundles: []BundleName{"no-debug"},
			Verify:  noChange,
		},
		{
			Name: "invalid flag",
			BundleConfig: map[BundleName]Bundle{
				"invalid-flag": {
					"not-a-real-flag": "nope.avi",
				},
			},
			Bundles: []BundleName{"invalid-flag"},
			WantErr: true,
		},
		{
			Name: "duplicate no-op bundles",
			BundleConfig: map[BundleName]Bundle{
				"empty": {},
				"no-debug": {
					"debug": "false",
				},
			},
			Bundles: []BundleName{"no-debug", "no-debug"},
			Verify:  noChange,
		},
		{
			Name: "simple bundle",
			BundleConfig: map[BundleName]Bundle{
				"empty": {},
				"debug": {
					"debug": "true",
				},
				"no-debug": {
					"debug": "false",
				},
			},
			Bundles: []BundleName{"debug"},
			Verify: func(t *testing.T, old, new *Config) {
				t.Helper()
				if old.Debug {
					t.Error("debug was previously set to true")
				}
				if !new.Debug {
					t.Error("debug was not set to true")
				}
			},
		},
		{
			Name: "incompatible bundles",
			BundleConfig: map[BundleName]Bundle{
				"debug": {
					"debug": "true",
				},
				"no-debug": {
					"debug": "false",
				},
			},
			Bundles: []BundleName{"debug", "no-debug"},
			WantErr: true,
		},
		{
			Name: "compatible bundles",
			BundleConfig: map[BundleName]Bundle{
				"debug": {
					"debug": "true",
				},
				"debug-and-profile": {
					"debug":   "true",
					"profile": "true",
				},
			},
			Bundles: []BundleName{"debug", "debug-and-profile"},
			Verify: func(t *testing.T, old, new *Config) {
				t.Helper()
				if old.Debug || old.ProfileEnable {
					t.Error("debug/profiling was previously set to true")
				}
				if !new.Debug {
					t.Error("debug was not set to true")
				}
				if !new.ProfileEnable {
					t.Error("profiling was not set to true")
				}
			},
		},
		{
			Name: "bundle takes precedence over command-line value",
			BundleConfig: map[BundleName]Bundle{
				"no-debug": {
					"debug": "false",
				},
			},
			CommandLine: []string{"-debug=true"},
			Bundles:     []BundleName{"no-debug"},
			Verify: func(t *testing.T, old, new *Config) {
				t.Helper()
				if new.Debug {
					t.Error("debug is still true")
				}
			},
		},
		{
			Name: "command line matching bundle value",
			BundleConfig: map[BundleName]Bundle{
				"debug": {
					"debug": "true",
				},
			},
			CommandLine: []string{"-debug=true"},
			Bundles:     []BundleName{"debug"},
			Verify: func(t *testing.T, old, new *Config) {
				t.Helper()
				noChange(t, old, new)
				if !new.Debug {
					t.Error("debug was set to false")
				}
			},
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			oldBundles := Bundles
			defer func() {
				Bundles = oldBundles
			}()
			Bundles = test.BundleConfig
			flagSet := flag.NewFlagSet(test.Name, flag.ContinueOnError)
			RegisterFlags(flagSet)
			if err := flagSet.Parse(test.CommandLine); err != nil {
				t.Fatalf("cannot parse command line %q: %v", test.CommandLine, err)
			}
			cfg, err := NewFromFlags(flagSet)
			if err != nil {
				t.Fatalf("cannot generate config from flags: %v", err)
			}
			oldCfg := *cfg
			err = cfg.ApplyBundles(flagSet, test.Bundles...)
			if test.WantErr && err == nil {
				t.Error("got no error, but expected one")
			}
			if !test.WantErr && err != nil {
				t.Errorf("got unexpected error: %v", err)
			}
			if t.Failed() {
				return
			}
			if err != nil && test.Verify != nil {
				t.Error("cannot specify Verify function for erroring tests")
			}
			if err == nil && test.Verify != nil {
				test.Verify(t, &oldCfg, cfg)
			}
		})
	}
}

func TestBundleValidate(t *testing.T) {
	defaultVerify := func(err error) error { return err }
	for _, tc := range []struct {
		name   string
		bundle Bundle
		verify func(err error) error
	}{
		{
			name:   "empty bundle",
			bundle: Bundle(map[string]string{}),
			verify: defaultVerify,
		},
		{
			name:   "invalid flag bundle",
			bundle: Bundle(map[string]string{"not-a-real-flag": "true"}),
			verify: func(err error) error {
				want := `unknown flag "not-a-real-flag"`
				if !strings.Contains(err.Error(), want) {
					return fmt.Errorf("mismatch error: got: %q want: %q", err.Error(), want)
				}
				return nil
			},
		},
		{
			name:   "invalid value",
			bundle: Bundle(map[string]string{"debug": "invalid"}),
			verify: func(err error) error {
				want := `parsing "invalid": invalid syntax`
				if !strings.Contains(err.Error(), want) {
					return fmt.Errorf("mismatch error: got: %q want: %q", err.Error(), want)
				}
				return nil
			},
		},
		{
			name:   "valid flag bundle",
			bundle: Bundle(map[string]string{"debug": "true"}),
			verify: defaultVerify,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.verify(tc.bundle.Validate()); err != nil {
				t.Fatalf("Validate failed: %v", err)
			}
		})
	}
}

func TestToContinerdConfigTOML(t *testing.T) {
	header := `binary_name = "%s"
root = "%s"
`
	opt := ContainerdConfigOptions{
		BinaryPath: "/path/to/runsc",
		RootPath:   "/path/to/root",
	}
	header = fmt.Sprintf(header, opt.BinaryPath, opt.RootPath)

	for _, tc := range []struct {
		name        string
		bundle      Bundle
		want        string
		createError error
	}{
		{
			name: "empty bundle",
			want: header,
		},
		{
			name:   "valid flag bundle",
			bundle: Bundle(map[string]string{"debug": "true"}),
			want: func() string {
				flagStr := "[runsc_config]\n  debug = \"true\"\n"
				return strings.Join([]string{header, flagStr}, "")
			}(),
		},
		{
			name:        "invalid flag bundle",
			bundle:      Bundle(map[string]string{"not-a-real-flag": "true"}),
			createError: fmt.Errorf("unknown flag \"not-a-real-flag\""),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewFromBundle(tc.bundle)
			if tc.createError != nil {
				if err == nil {
					t.Fatalf("got no error, but expected one")
				}
				if !strings.Contains(err.Error(), tc.createError.Error()) {
					t.Fatalf("mismatch error: got: %q want: %q", err.Error(), tc.createError.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("NewFromBundle failed: %v", err)
			}

			toml, err := cfg.ToContainerdConfigTOML(opt)
			if err != nil {
				t.Fatalf("ToContainerdConfigTOML failed: %v", err)
			}
			if diff := cmp.Diff(tc.want, toml); diff != "" {
				t.Fatalf("mismatch strings: %s", diff)
			}

		})
	}

}
