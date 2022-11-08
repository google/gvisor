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

// Package flags contains globally-visible flags.
package flags

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"gvisor.dev/gvisor/runsc/flag"
)

var (
	// Go location.
	Go string

	// GOOS defines the GOOS for analysis.
	GOOS string

	// GOARCH defines the GOARCH for analysis.
	GOARCH string

	// BuildTags defines the set of build tags for analysis. Note that
	// while this may also be a StringList, it is kept as an explicit
	// comma-separated list in order to build the standard flag.
	BuildTags string

	// ImportMap defines all binary input files.
	ImportMap = StringMap{}

	// ArchiveMap defines all binary archive files.
	ArchiveMap = StringMap{}

	// FactMap defines all fact input files.
	FactMap = StringMap{}

	// Bundles define fact bundles. This is typically used to contain the
	// inputs for the standard library.
	Bundles StringList
)

func init() {
	flag.StringVar(&Go, "go", "go", "command used to invoke 'go tool'")
	flag.StringVar(&GOOS, "GOOS", runtime.GOOS, "GOOS for analysis")
	flag.StringVar(&GOARCH, "GOARCH", runtime.GOARCH, "GOARCH for analysis")
	flag.StringVar(&BuildTags, "tags", "", "comma-separated build tags")
	flag.Var(&ImportMap, "import", "map of import paths to binaries")
	flag.Var(&ArchiveMap, "archive", "map of import paths to archives")
	flag.Var(&FactMap, "facts", "map of import paths to facts")
	flag.Var(&Bundles, "bundle", "list of fact bundles")
}

// StringList is a list of strings.
type StringList []string

// String implements fmt.Stringer.String.
func (s *StringList) String() string {
	return strings.Join((*s), ",")
}

// Set implements flag.Value.Set.
func (s *StringList) Set(value string) error {
	(*s) = append((*s), value)
	return nil
}

// Get implements flag.Value.Get.
func (s *StringList) Get() any {
	return *s
}

// StringMap is a string to string map.
type StringMap map[string]string

// String implements fmt.Stringer.String.
func (s *StringMap) String() string {
	parts := make([]string, 0, len(*s))
	for k, v := range *s {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, ",")
}

// Get implements flag.Value.Get.
func (s *StringMap) Get() any {
	return *s
}

// Set implements flag.Value.Set.
func (s *StringMap) Set(value string) error {
	if (*s) == nil {
		(*s) = make(map[string]string)
	}
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		// We specify the flag as -x=y=z. This string missed the second '='.
		return fmt.Errorf("invalid format: expected at least one '=' in flag value, got %q", value)
	}
	(*s)[parts[0]] = parts[1]
	return nil
}

var (
	envOnce sync.Once
	envErr  error
	envMap  = map[string]string{}
)

// Env gets a Go environment value.
func Env(value string) (string, error) {
	if v := os.Getenv(value); v != "" {
		return v, nil
	}
	envOnce.Do(func() {
		// Pull the go environment.
		cmd := exec.Command(Go, "env", "-json")
		output, err := cmd.Output()
		if err != nil {
			envErr = fmt.Errorf("error executing 'go env -json': %w", err)
			return
		}
		dec := json.NewDecoder(bytes.NewBuffer(output))
		if err := dec.Decode(&envMap); err != nil {
			envErr = fmt.Errorf("error decoding 'go env -json': %w", err)
			return
		}
	})
	return envMap[value], envErr // From above.
}
