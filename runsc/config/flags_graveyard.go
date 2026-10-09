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
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/runsc/flag"
)

var deprecatedFlags sync.Map // map[string]*time.Time

// WarnOnDeprecatedFlagUsage prints a warning message for any deprecated flags
// that are set in the given flag set.
func WarnOnDeprecatedFlagUsage(flagSet *flag.FlagSet) {
	flagSet.Visit(func(f *flag.Flag) {
		if deprecationDateAny, ok := deprecatedFlags.Load(f.Name); ok {
			deprecationDate := deprecationDateAny.(*time.Time)
			fmt.Fprintf(os.Stderr, "\033[1mWARNING\033[0m: --%s is deprecated. Expect it to be removed by %s.\n--%s usage: %s\n\n",
				f.Name, deprecationDate.Format("2006-01"), f.Name, f.Usage)
		}
	})
}

func deprecatedBool(flagSet *flag.FlagSet, name string, defaultValue bool, usage string, removalDate time.Time) {
	flagSet.Bool(name, defaultValue, usage)
	deprecatedFlags.LoadOrStore(name, &removalDate)
}

func deprecatedVar(flagSet *flag.FlagSet, value flag.Value, name string, usage string, removalDate time.Time) {
	flagSet.Var(value, name, usage)
	deprecatedFlags.LoadOrStore(name, &removalDate)
}

// sidecarUsagePolicy is the value of the retired --sidecar-usage-policy flag.
// Its LEGACY_DEPRECATED_SLOW_EMBEDDED_FALLBACK value selected the embedded
// sidecar fallback, which no longer exists, so that value is rejected with an
// explanation. The other values never did anything that is not now the
// default, so they are accepted and ignored.
type sidecarUsagePolicy string

// Set implements flag.Value.
func (p *sidecarUsagePolicy) Set(v string) error {
	switch strings.ToUpper(v) {
	case "DEFAULT", "STRICT":
		*p = sidecarUsagePolicy(strings.ToUpper(v))
		return nil
	case "LEGACY_DEPRECATED_SLOW_EMBEDDED_FALLBACK":
		return fmt.Errorf("the embedded sidecar fallback has been removed; install the sidecar binaries per https://gvisor.dev/docs/user_guide/install/ instructions and drop this flag")
	}
	return fmt.Errorf("invalid value %q; must be DEFAULT or STRICT", v)
}

// String implements flag.Value.
func (p *sidecarUsagePolicy) String() string {
	return string(*p)
}

// Get implements flag.Getter.
func (p *sidecarUsagePolicy) Get() any {
	return string(*p)
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
	deprecatedBool(flagSet, "save-restore-netstack", true, "DEPRECATED: this flag has no effect.", time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC))
	deprecatedBool(flagSet, "mount-cgroup-v2", false, "DEPRECATED: use in-sandbox-cgroup=v2", time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC))
	usagePolicy := sidecarUsagePolicy("DEFAULT")
	deprecatedVar(flagSet, &usagePolicy, "sidecar-usage-policy", "DEPRECATED: this flag has no effect; sidecar binaries must always be installed in `gvisor-bin` (or `GVISOR_SIDECAR_BINARIES_DIR`).", time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC))
}
