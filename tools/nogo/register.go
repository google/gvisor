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

package nogo

import (
	"encoding/gob"
	"log"

	"golang.org/x/tools/go/analysis"
)

// analyzers returns all configured analyzers.
func analyzers() (all []*analysis.Analyzer) {
	for a, _ := range analyzerConfig {
		all = append(all, a)
	}
	return all
}

func init() {
	// Validate basic configuration.
	if err := analysis.Validate(analyzers()); err != nil {
		log.Fatalf("unable to validate analyzer: %v", err)
	}

	// Register all fact types.
	//
	// N.B. This needs to be done recursively, because there may be
	// analyzers in the Requires list that do not appear explicitly above.
	registered := make(map[*analysis.Analyzer]struct{})
	var register func(*analysis.Analyzer)
	register = func(a *analysis.Analyzer) {
		if _, ok := registered[a]; ok {
			return
		}

		// Regsiter dependencies.
		for _, da := range a.Requires {
			register(da)
		}

		// Register local facts.
		for _, f := range a.FactTypes {
			gob.Register(f)
		}

		registered[a] = struct{}{} // Done.
	}
	for _, a := range analyzers() {
		register(a)
	}
}
