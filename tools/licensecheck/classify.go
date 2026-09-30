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

package licensecheck

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	textlicense "github.com/google/licensecheck"
)

// The registry owns both text patterns and identifiers accepted in explicit
// metadata. Verifying metadata does not require compiling the scanner.
type licenseRegistry struct {
	patterns []textlicense.License
	ids      map[License]struct{}
}

var configuredLicenses = sync.OnceValues(func() (licenseRegistry, error) {
	patterns := textlicense.BuiltinLicenses()
	apache := slices.IndexFunc(patterns, func(license textlicense.License) bool {
		return license.ID == "Apache-2.0" && license.LRE != ""
	})
	if apache < 0 {
		return licenseRegistry{}, errors.New("license scanner has no Apache-2.0 text pattern")
	}
	// Match the complete exception after Apache's pattern. The scanner chooses
	// the longest match, so this supersedes ordinary Apache only when both texts
	// are present. v0.3.1 has no builtin LLVM exception pattern.
	patterns = append(patterns, textlicense.License{
		ID:  "Apache-2.0 WITH LLVM-exception",
		LRE: patterns[apache].LRE + "\n" + llvmException,
	})
	// NOASSERTION is explicit metadata for inputs without a software license,
	// such as certificate bundles. It is never inferred from license text.
	ids := map[License]struct{}{"NOASSERTION": {}}
	for _, license := range patterns {
		ids[License(license.ID)] = struct{}{}
	}
	return licenseRegistry{patterns: patterns, ids: ids}, nil
})

var licenseScanner = sync.OnceValues(func() (*textlicense.Scanner, error) {
	registry, err := configuredLicenses()
	if err != nil {
		return nil, err
	}
	return textlicense.NewScanner(registry.patterns)
})

// classify reports disjoint recognized license texts. Detection is heuristic;
// identifiers are kept literal, including ambiguous GNU license versions.
func classify(text string) (Licenses, error) {
	scanner, err := licenseScanner()
	if err != nil {
		return nil, fmt.Errorf("cannot configure license scanner: %w", err)
	}
	var ids Licenses
	for _, match := range scanner.Scan([]byte(text)).Match {
		// A reference URL alone is not the dependency's license grant.
		if !match.IsURL {
			ids = append(ids, License(match.ID))
		}
	}
	if len(ids) == 0 {
		return nil, errors.New("cannot classify license text")
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// Complete exception text from LLVM's license. LREs ignore punctuation and
// case, so no phrase normalization or secondary detection path is needed.
// https://github.com/llvm/llvm-project/blob/85ac56026/LICENSE.TXT#L208-L222
const llvmException = `LLVM Exceptions to the Apache 2.0 License

As an exception, if, as a result of your compiling your source code, portions
of this Software are embedded into an Object form of such source code, you
may redistribute such embedded portions in such Object form without complying
with the conditions of Sections 4(a), 4(b) and 4(d) of the License.

In addition, if you combine or link compiled forms of this Software with
software that is licensed under the GPLv2 ("Combined Software") and if a
court of competent jurisdiction determines that the patent provision (Section
3), the indemnity provision (Section 9) or other Section of the License
conflicts with the conditions of the GPLv2, you may retroactively and
prospectively choose to deem waived or otherwise exclude such Section(s) of
the License, but only in their entirety and only with respect to the Combined
Software.
`
