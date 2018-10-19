// Copyright 2018 Google LLC
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

// Helper tool to configure Docker daemon.
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"context"
	"flag"
	"github.com/google/subcommands"
)

var (
	configFile = flag.String("config_file", "/etc/docker/daemon.json", "path to Docker daemon config file")
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(&runtimeAdd{}, "")
	subcommands.Register(&runtimeRemove{}, "")

	// All subcommands must be registered before flag parsing.
	flag.Parse()

	exitCode := subcommands.Execute(context.Background())
	os.Exit(int(exitCode))
}

type runtime struct {
	Path        string   `json:"path,omitempty"`
	RuntimeArgs []string `json:"runtimeArgs,omitempty"`
}

// runtimeAdd implements subcommands.Command.
type runtimeAdd struct {
}

// Name implements subcommands.Command.Name.
func (*runtimeAdd) Name() string {
	return "runtime-add"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*runtimeAdd) Synopsis() string {
	return "adds a runtime to docker daemon configuration"
}

// Usage implements subcommands.Command.Usage.
func (*runtimeAdd) Usage() string {
	return `runtime-add [flags] <name> <path> [args...]  -- if provided, args are passed as arguments to the runtime
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (*runtimeAdd) SetFlags(*flag.FlagSet) {
}

// Execute implements subcommands.Command.Execute.
func (r *runtimeAdd) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() < 2 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	name := f.Arg(0)
	path := f.Arg(1)
	runtimeArgs := f.Args()[2:]

	fmt.Printf("Adding runtime %q to file %q\n", name, *configFile)
	c, err := readConfig(*configFile)
	if err != nil {
		log.Fatalf("Error reading config file %q: %v", *configFile, err)
	}

	var rts map[string]interface{}
	if i, ok := c["runtimes"]; ok {
		rts = i.(map[string]interface{})
	} else {
		rts = make(map[string]interface{})
		c["runtimes"] = rts
	}
	rts[name] = runtime{Path: path, RuntimeArgs: runtimeArgs}

	if err := writeConfig(c, *configFile); err != nil {
		log.Fatalf("Error writing config file %q: %v", *configFile, err)
	}
	return subcommands.ExitSuccess
}

// runtimeRemove implements subcommands.Command.
type runtimeRemove struct {
}

// Name implements subcommands.Command.Name.
func (*runtimeRemove) Name() string {
	return "runtime-rm"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*runtimeRemove) Synopsis() string {
	return "removes a runtime from docker daemon configuration"
}

// Usage implements subcommands.Command.Usage.
func (*runtimeRemove) Usage() string {
	return `runtime-rm [flags] <name>
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (*runtimeRemove) SetFlags(*flag.FlagSet) {
}

// Execute implements subcommands.Command.Execute.
func (r *runtimeRemove) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	name := f.Arg(0)

	fmt.Printf("Removing runtime %q from file %q\n", name, *configFile)
	c, err := readConfig(*configFile)
	if err != nil {
		log.Fatalf("Error reading config file %q: %v", *configFile, err)
	}

	var rts map[string]interface{}
	if i, ok := c["runtimes"]; ok {
		rts = i.(map[string]interface{})
	} else {
		log.Fatalf("runtime %q not found", name)
	}
	if _, ok := rts[name]; !ok {
		log.Fatalf("runtime %q not found", name)
	}
	delete(rts, name)

	if err := writeConfig(c, *configFile); err != nil {
		log.Fatalf("Error writing config file %q: %v", *configFile, err)
	}
	return subcommands.ExitSuccess
}

func readConfig(path string) (map[string]interface{}, error) {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	c := make(map[string]interface{})
	if len(configBytes) > 0 {
		if err := json.Unmarshal(configBytes, &c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func writeConfig(c map[string]interface{}, path string) error {
	b, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}

	if err := os.Rename(path, path+"~"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error renaming config file %q: %v", path, err)
	}
	if err := ioutil.WriteFile(path, b, 0644); err != nil {
		return fmt.Errorf("error writing config file %q: %v", path, err)
	}
	return nil
}
