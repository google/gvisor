// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"os"
	"time"

	"gvisor.dev/gvisor/runsc/flag"
)

var deprecatedFlags map[string]time.Time = make(map[string]time.Time)

// WarnOnDeprecatedFlagUsage prints a warning message for any deprecated flags
// that are set in the given flag set.
func WarnOnDeprecatedFlagUsage(flagSet *flag.FlagSet) {
	flagSet.Visit(func(f *flag.Flag) {
		if deprecationDate, ok := deprecatedFlags[f.Name]; ok {
			fmt.Fprintf(os.Stderr, "\033[1mWARNING\033[0m: --%s is deprecated. Expect it to be removed by %s.\n--%s usage: %s\n\n",
				f.Name, deprecationDate.Format("2006-01"), f.Name, f.Usage)
		}
	})
}

func deprecatedBool(flagSet *flag.FlagSet, name string, defaultValue bool, usage string, removalDate time.Time) {
	flagSet.Bool(name, defaultValue, usage)
	deprecatedFlags[name] = removalDate
}

// RegisterDeprecatedFlags registers flags that should no longer be used and
// are planned for removal.
func RegisterDeprecatedFlags(flagSet *flag.FlagSet) {
	deprecatedBool(flagSet, "buffer-pooling", true, "DEPRECATED: this flag has no effect.", time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC))
	deprecatedBool(flagSet, "vfs2", true, "DEPRECATED: this flag has no effect.", time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC))
	deprecatedBool(flagSet, "fuse", true, "DEPRECATED: this flag has no effect.", time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC))
	deprecatedBool(flagSet, "lisafs", true, "DEPRECATED: this flag has no effect.", time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC))
	deprecatedBool(flagSet, "cgroupfs", false, "DEPRECATED: this flag has no effect.", time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC))
	deprecatedBool(flagSet, "fsgofer-host-uds", false, "DEPRECATED: use host-uds=all", time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC))
}
