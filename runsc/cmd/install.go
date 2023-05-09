// Copyright 2019 The gVisor Authors.
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
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// Install implements subcommands.Command.
type Install struct {
	ConfigFile     string
	Runtime        string
	Experimental   bool
	Clobber        bool
	CgroupDriver   string
	executablePath string
	runtimeArgs    []string
}

// Name implements subcommands.Command.Name.
func (*Install) Name() string {
	return "install"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Install) Synopsis() string {
	return "adds a runtime to docker daemon configuration"
}

// Usage implements subcommands.Command.Usage.
func (*Install) Usage() string {
	return `install [flags] <name> [-- [args...]] -- if provided, args are passed to the runtime
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (i *Install) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&i.ConfigFile, "config_file", "/etc/docker/daemon.json", "path to Docker daemon config file")
	fs.StringVar(&i.Runtime, "runtime", "runsc", "runtime name")
	fs.BoolVar(&i.Experimental, "experimental", false, "enable/disable experimental features")
	fs.BoolVar(&i.Clobber, "clobber", true, "clobber existing runtime configuration")
	fs.StringVar(&i.CgroupDriver, "cgroupdriver", "", "docker cgroup driver")
}

// Execute implements subcommands.Command.Execute.
func (i *Install) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	// Grab the name and arguments.
	i.runtimeArgs = f.Args()
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	config.RegisterFlags(testFlags)
	testFlags.Parse(i.runtimeArgs)
	conf, err := config.NewFromFlags(testFlags)
	if err != nil {
		log.Fatalf("invalid runtime arguments: %v", err)
	}

	// Check the platform.
	p, err := platform.Lookup(conf.Platform)
	if err != nil {
		log.Fatalf("invalid platform: %v", err)
	}
	deviceFile, err := p.OpenDevice(conf.PlatformDevicePath)
	if err != nil {
		log.Printf("WARNING: unable to open platform, runsc may fail to start: %v", err)
	}
	if deviceFile != nil {
		deviceFile.Close()
	}

	// Extract the executable.
	path, err := os.Executable()
	if err != nil {
		log.Fatalf("Error reading current exectuable: %v", err)
	}

	i.executablePath = path

	installRW := configReaderWriter{
		read:  defaultReadConfig,
		write: defaultWriteConfig,
	}

	if err := doInstallConfig(i, installRW); err != nil {
		log.Fatalf("Install failed: %v", err)
	}

	// Success.
	log.Print("Successfully updated config.")
	return subcommands.ExitSuccess
}

func doInstallConfig(i *Install, rw configReaderWriter) error {
	// Load the configuration file.
	configBytes, err := rw.read(i.ConfigFile)
	if err != nil {
		return fmt.Errorf("error reading config file %q: %v", i.ConfigFile, err)
	}
	// Unmarshal the configuration.
	c := make(map[string]any)
	if len(configBytes) > 0 {
		if err := json.Unmarshal(configBytes, &c); err != nil {
			return err
		}
	}

	// Add the given runtime.
	var rts map[string]any
	if i, ok := c["runtimes"]; ok {
		rts = i.(map[string]any)
	} else {
		rts = make(map[string]any)
		c["runtimes"] = rts
	}
	updateRuntime := func() {
		rts[i.Runtime] = struct {
			Path        string   `json:"path,omitempty"`
			RuntimeArgs []string `json:"runtimeArgs,omitempty"`
		}{
			Path:        i.executablePath,
			RuntimeArgs: i.runtimeArgs,
		}
	}
	_, ok := rts[i.Runtime]
	switch {
	case !ok:
		log.Printf("Runtime %s not found: adding\n", i.Runtime)
		updateRuntime()
	case i.Clobber:
		log.Printf("Clobber is set. Overwriting runtime %s not found: adding\n", i.Runtime)
		updateRuntime()
	default:
		log.Printf("Not overwriting runtime %s\n", i.Runtime)
	}

	// Set experimental if required.
	if i.Experimental {
		c["experimental"] = true
	}

	re := regexp.MustCompile(`^native.cgroupdriver=`)
	// Set the cgroupdriver if required.
	if i.CgroupDriver != "" {
		v, ok := c["exec-opts"]
		if !ok {
			c["exec-opts"] = []string{fmt.Sprintf("native.cgroupdriver=%s", i.CgroupDriver)}
		} else {
			opts := v.([]any)
			newOpts := []any{}
			for _, opt := range opts {
				if !i.Clobber {
					newOpts = opts
					break
				}
				o, ok := opt.(string)
				if !ok {
					continue
				}

				if !re.MatchString(o) {
					newOpts = append(newOpts, o)
				}
			}
			c["exec-opts"] = append(newOpts, fmt.Sprintf("native.cgroupdriver=%s", i.CgroupDriver))
		}
	}

	// Write out the runtime.
	if err := rw.write(c, i.ConfigFile); err != nil {
		return fmt.Errorf("error writing config file %q: %v", i.ConfigFile, err)
	}
	return nil
}

// Uninstall implements subcommands.Command.
type Uninstall struct {
	ConfigFile string
	Runtime    string
}

// Name implements subcommands.Command.Name.
func (*Uninstall) Name() string {
	return "uninstall"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Uninstall) Synopsis() string {
	return "removes a runtime from docker daemon configuration"
}

// Usage implements subcommands.Command.Usage.
func (*Uninstall) Usage() string {
	return `uninstall [flags] <name>
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (u *Uninstall) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&u.ConfigFile, "config_file", "/etc/docker/daemon.json", "path to Docker daemon config file")
	fs.StringVar(&u.Runtime, "runtime", "runsc", "runtime name")
}

// Execute implements subcommands.Command.Execute.
func (u *Uninstall) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	log.Printf("Removing runtime %q from %q.", u.Runtime, u.ConfigFile)
	if err := doUninstallConfig(u, configReaderWriter{
		read:  defaultReadConfig,
		write: defaultWriteConfig,
	}); err != nil {
		log.Fatalf("Uninstall failed: %v", err)
	}
	return subcommands.ExitSuccess
}

func doUninstallConfig(u *Uninstall, rw configReaderWriter) error {
	configBytes, err := rw.read(u.ConfigFile)
	if err != nil {
		return fmt.Errorf("error reading config file %q: %v", u.ConfigFile, err)
	}

	// Unmarshal the configuration.
	c := make(map[string]any)
	if len(configBytes) > 0 {
		if err := json.Unmarshal(configBytes, &c); err != nil {
			return err
		}
	}

	var rts map[string]any
	if i, ok := c["runtimes"]; ok {
		rts = i.(map[string]any)
	} else {
		return fmt.Errorf("runtime %q not found", u.Runtime)
	}
	if _, ok := rts[u.Runtime]; !ok {
		return fmt.Errorf("runtime %q not found", u.Runtime)
	}
	delete(rts, u.Runtime)

	if err := rw.write(c, u.ConfigFile); err != nil {
		return fmt.Errorf("error writing config file %q: %v", u.ConfigFile, err)
	}
	return nil
}

type configReaderWriter struct {
	read  func(string) ([]byte, error)
	write func(map[string]any, string) error
}

func defaultReadConfig(path string) ([]byte, error) {
	// Read the configuration data.
	configBytes, err := ioutil.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return configBytes, nil
}

func defaultWriteConfig(c map[string]any, filename string) error {
	// Marshal the configuration.
	b, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}

	// Copy the old configuration.
	old, err := ioutil.ReadFile(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("error reading config file %q: %v", filename, err)
		}
	} else {
		if err := ioutil.WriteFile(filename+"~", old, 0644); err != nil {
			return fmt.Errorf("error backing up config file %q: %v", filename, err)
		}
	}

	// Make the necessary directories.
	if err := os.MkdirAll(path.Dir(filename), 0755); err != nil {
		return fmt.Errorf("error creating config directory for %q: %v", filename, err)
	}

	// Write the new configuration.
	if err := ioutil.WriteFile(filename, b, 0644); err != nil {
		return fmt.Errorf("error writing config file %q: %v", filename, err)
	}

	return nil
}
