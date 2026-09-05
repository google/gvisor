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

// Binary licensecheck audits the licenses of gVisor's external dependencies.
package main

import (
	"flag"
	"fmt"
	"os"

	"gvisor.dev/gvisor/tools/licensecheck"
)

var (
	mode     = flag.String("mode", "", "one of: fetch, verify")
	goMod    = flag.String("go_mod", "go.mod", "path to go.mod")
	yamlPath = flag.String("yaml", "tools/licensecheck/dependencies.yaml", "path to the license YAML file")
	policy   = flag.String("policy", "governance/licensing.yaml", "path to the licensing policy YAML file")
)

func main() {
	flag.Parse()
	if wd := os.Getenv("BUILD_WORKSPACE_DIRECTORY"); wd != "" {
		if err := os.Chdir(wd); err != nil {
			fmt.Fprintf(os.Stderr, "licensecheck: %v\n", err)
			os.Exit(1)
		}
	}
	p := licensecheck.Paths{
		GoMod:  *goMod,
		YAML:   *yamlPath,
		Policy: *policy,
	}
	var err error
	switch *mode {
	case "fetch":
		err = licensecheck.Fetch(p)
	case "verify":
		err = licensecheck.Verify(p)
	default:
		fmt.Fprintln(os.Stderr, "usage: licensecheck --mode=fetch|verify")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "licensecheck: %v\n", err)
		os.Exit(1)
	}
}
