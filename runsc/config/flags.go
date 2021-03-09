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
	"os"
	"path/filepath"
	"reflect"
	"strconv"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/runsc/flag"
)

var registration sync.Once

// RegisterFlags registers flags used to populate Config.
func RegisterFlags() {
	registration.Do(func() {
		// Although these flags are not part of the OCI spec, they are used by
		// Docker, and thus should not be changed.
		flag.String("root", "", "root directory for storage of container state.")
		flag.String("log", "", "file path where internal debug information is written, default is stdout.")
		flag.String("log-format", "text", "log format: text (default), json, or json-k8s.")
		flag.Bool("debug", false, "enable debug logging.")

		// These flags are unique to runsc, and are used to configure parts of the
		// system that are not covered by the runtime spec.

		// Debugging flags.
		flag.String("debug-log", "", "additional location for logs. If it ends with '/', log files are created inside the directory with default names. The following variables are available: %TIMESTAMP%, %COMMAND%.")
		flag.String("panic-log", "", "file path were panic reports and other Go's runtime messages are written.")
		flag.Bool("log-packets", false, "enable network packet logging.")
		flag.String("debug-log-format", "text", "log format: text (default), json, or json-k8s.")
		flag.Bool("alsologtostderr", false, "send log messages to stderr.")
		flag.Bool("allow-flag-override", false, "allow OCI annotations (dev.gvisor.flag.<name>) to override flags for debugging.")
		flag.String("traceback", "system", "golang runtime's traceback level")

		// Debugging flags: strace related
		flag.Bool("strace", false, "enable strace.")
		flag.String("strace-syscalls", "", "comma-separated list of syscalls to trace. If --strace is true and this list is empty, then all syscalls will be traced.")
		flag.Uint("strace-log-size", 1024, "default size (in bytes) to log data argument blobs.")

		// Flags that control sandbox runtime behavior.
		flag.String("platform", "ptrace", "specifies which platform to use: ptrace (default), kvm.")
		flag.Var(watchdogActionPtr(watchdog.LogWarning), "watchdog-action", "sets what action the watchdog takes when triggered: log (default), panic.")
		flag.Int("panic-signal", -1, "register signal handling that panics. Usually set to SIGUSR2(12) to troubleshoot hangs. -1 disables it.")
		flag.Bool("profile", false, "prepares the sandbox to use Golang profiler. Note that enabling profiler loosens the seccomp protection added to the sandbox (DO NOT USE IN PRODUCTION).")
		flag.Bool("rootless", false, "it allows the sandbox to be started with a user that is not root. Sandbox and Gofer processes may run with same privileges as current user.")
		flag.Var(leakModePtr(refs.NoLeakChecking), "ref-leak-mode", "sets reference leak check mode: disabled (default), log-names, log-traces.")
		flag.Bool("cpu-num-from-quota", false, "set cpu number to cpu quota (least integer greater or equal to quota value, but not less than 2)")
		flag.Bool("oci-seccomp", false, "Enables loading OCI seccomp filters inside the sandbox.")

		// Flags that control sandbox runtime behavior: FS related.
		flag.Var(fileAccessTypePtr(FileAccessExclusive), "file-access", "specifies which filesystem to use for the root mount: exclusive (default), shared. Volume mounts are always shared.")
		flag.Bool("overlay", false, "wrap filesystem mounts with writable overlay. All modifications are stored in memory inside the sandbox.")
		flag.Bool("verity", false, "specifies whether a verity file system will be mounted.")
		flag.Bool("overlayfs-stale-read", true, "assume root mount is an overlay filesystem")
		flag.Bool("fsgofer-host-uds", false, "allow the gofer to mount Unix Domain Sockets.")
		flag.Bool("vfs2", false, "enables VFSv2. This uses the new VFS layer that is faster than the previous one.")
		flag.Bool("fuse", false, "TEST ONLY; use while FUSE in VFSv2 is landing. This allows the use of the new experimental FUSE filesystem.")

		// Flags that control sandbox runtime behavior: network related.
		flag.Var(networkTypePtr(NetworkSandbox), "network", "specifies which network to use: sandbox (default), host, none. Using network inside the sandbox is more secure because it's isolated from the host network.")
		flag.Bool("net-raw", false, "enable raw sockets. When false, raw sockets are disabled by removing CAP_NET_RAW from containers (`runsc exec` will still be able to utilize raw sockets). Raw sockets allow malicious containers to craft packets and potentially attack the network.")
		flag.Bool("gso", true, "enable hardware segmentation offload if it is supported by a network device.")
		flag.Bool("software-gso", true, "enable software segmentation offload when hardware offload can't be enabled.")
		flag.Bool("tx-checksum-offload", false, "enable TX checksum offload.")
		flag.Bool("rx-checksum-offload", true, "enable RX checksum offload.")
		flag.Var(queueingDisciplinePtr(QDiscFIFO), "qdisc", "specifies which queueing discipline to apply by default to the non loopback nics used by the sandbox.")
		flag.Int("num-network-channels", 1, "number of underlying channels(FDs) to use for network link endpoints.")

		// Test flags, not to be used outside tests, ever.
		flag.Bool("TESTONLY-unsafe-nonroot", false, "TEST ONLY; do not ever use! This skips many security measures that isolate the host from the sandbox.")
		flag.String("TESTONLY-test-name-env", "", "TEST ONLY; do not ever use! Used for automated tests to improve logging.")
	})
}

// NewFromFlags creates a new Config with values coming from command line flags.
func NewFromFlags() (*Config, error) {
	conf := &Config{}

	obj := reflect.ValueOf(conf).Elem()
	st := obj.Type()
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		name, ok := f.Tag.Lookup("flag")
		if !ok {
			// No flag set for this field.
			continue
		}
		fl := flag.CommandLine.Lookup(name)
		if fl == nil {
			panic(fmt.Sprintf("Flag %q not found", name))
		}
		x := reflect.ValueOf(flag.Get(fl.Value))
		obj.Field(i).Set(x)
	}

	if len(conf.RootDir) == 0 {
		// If not set, set default root dir to something (hopefully) user-writeable.
		conf.RootDir = "/var/run/runsc"
		if runtimeDir, ok := os.LookupEnv("XDG_RUNTIME_DIR"); ok {
			conf.RootDir = filepath.Join(runtimeDir, "runsc")
		}
	}

	if err := conf.validate(); err != nil {
		return nil, err
	}
	return conf, nil
}

// ToFlags returns a slice of flags that correspond to the given Config.
func (c *Config) ToFlags() []string {
	var rv []string

	obj := reflect.ValueOf(c).Elem()
	st := obj.Type()
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		name, ok := f.Tag.Lookup("flag")
		if !ok {
			// No flag set for this field.
			continue
		}
		val := getVal(obj.Field(i))

		flag := flag.CommandLine.Lookup(name)
		if flag == nil {
			panic(fmt.Sprintf("Flag %q not found", name))
		}
		if val == flag.DefValue {
			continue
		}
		rv = append(rv, fmt.Sprintf("--%s=%s", flag.Name, val))
	}
	return rv
}

// Override writes a new value to a flag.
func (c *Config) Override(name string, value string) error {
	if !c.AllowFlagOverride {
		return fmt.Errorf("flag override disabled, use --allow-flag-override to enable it")
	}

	obj := reflect.ValueOf(c).Elem()
	st := obj.Type()
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		fieldName, ok := f.Tag.Lookup("flag")
		if !ok || fieldName != name {
			// Not a flag field, or flag name doesn't match.
			continue
		}
		fl := flag.CommandLine.Lookup(name)
		if fl == nil {
			// Flag must exist if there is a field match above.
			panic(fmt.Sprintf("Flag %q not found", name))
		}

		// Use flag to convert the string value to the underlying flag type, using
		// the same rules as the command-line for consistency.
		if err := fl.Value.Set(value); err != nil {
			return fmt.Errorf("error setting flag %s=%q: %w", name, value, err)
		}
		x := reflect.ValueOf(flag.Get(fl.Value))
		obj.Field(i).Set(x)

		// Validates the config again to ensure it's left in a consistent state.
		return c.validate()
	}
	return fmt.Errorf("flag %q not found. Cannot set it to %q", name, value)
}

func getVal(field reflect.Value) string {
	if str, ok := field.Addr().Interface().(fmt.Stringer); ok {
		return str.String()
	}
	switch field.Kind() {
	case reflect.Bool:
		return strconv.FormatBool(field.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(field.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(field.Uint(), 10)
	case reflect.String:
		return field.String()
	default:
		panic("unknown type " + field.Kind().String())
	}
}
