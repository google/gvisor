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

	"flag"
	"github.com/google/subcommands"
)

// Install implements subcommands.Command.
type Install struct {
	ConfigFile   string
	Runtime      string
	Experimental bool
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
	fs.BoolVar(&i.Experimental, "experimental", false, "enable experimental features")
}

// Execute implements subcommands.Command.Execute.
func (i *Install) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	// Grab the name and arguments.
	runtimeArgs := f.Args()

	// Extract the executable.
	path, err := os.Executable()
	if err != nil {
		log.Fatalf("Error reading current exectuable: %v", err)
	}

	// Load the configuration file.
	c, err := readConfig(i.ConfigFile)
	if err != nil {
		log.Fatalf("Error reading config file %q: %v", i.ConfigFile, err)
	}

	// Add the given runtime.
	var rts map[string]interface{}
	if i, ok := c["runtimes"]; ok {
		rts = i.(map[string]interface{})
	} else {
		rts = make(map[string]interface{})
		c["runtimes"] = rts
	}
	rts[i.Runtime] = struct {
		Path        string   `json:"path,omitempty"`
		RuntimeArgs []string `json:"runtimeArgs,omitempty"`
	}{
		Path:        path,
		RuntimeArgs: runtimeArgs,
	}

	// Set experimental if required.
	if i.Experimental {
		c["experimental"] = true
	}

	// Write out the runtime.
	if err := writeConfig(c, i.ConfigFile); err != nil {
		log.Fatalf("Error writing config file %q: %v", i.ConfigFile, err)
	}

	// Success.
	log.Printf("Added runtime %q with arguments %v to %q.", i.Runtime, runtimeArgs, i.ConfigFile)
	return subcommands.ExitSuccess
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
func (u *Uninstall) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	log.Printf("Removing runtime %q from %q.", u.Runtime, u.ConfigFile)

	c, err := readConfig(u.ConfigFile)
	if err != nil {
		log.Fatalf("Error reading config file %q: %v", u.ConfigFile, err)
	}

	var rts map[string]interface{}
	if i, ok := c["runtimes"]; ok {
		rts = i.(map[string]interface{})
	} else {
		log.Fatalf("runtime %q not found", u.Runtime)
	}
	if _, ok := rts[u.Runtime]; !ok {
		log.Fatalf("runtime %q not found", u.Runtime)
	}
	delete(rts, u.Runtime)

	if err := writeConfig(c, u.ConfigFile); err != nil {
		log.Fatalf("Error writing config file %q: %v", u.ConfigFile, err)
	}
	return subcommands.ExitSuccess
}

func readConfig(path string) (map[string]interface{}, error) {
	// Read the configuration data.
	configBytes, err := ioutil.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// Unmarshal the configuration.
	c := make(map[string]interface{})
	if len(configBytes) > 0 {
		if err := json.Unmarshal(configBytes, &c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func writeConfig(c map[string]interface{}, filename string) error {
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
