// Copyright The Isola Authors
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

package installer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// preflight binds systemd, the selected configuration and the CRI endpoint to
// the same live containerd, then proves that it serves this installer pod.
func (i *Installer) preflight(ctx context.Context, recovering bool) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := i.host.Run(ctx, "systemctl", "show", i.cfg.ContainerdService, "--property=LoadState,ActiveState,MainPID,ExecStart,KillMode")
	if err != nil {
		return fmt.Errorf("querying containerd systemd unit: %w", err)
	}
	props := parseProperties(out)
	if props["LoadState"] != "loaded" {
		return fmt.Errorf("containerd service is not loaded")
	}
	if props["KillMode"] != "process" {
		return fmt.Errorf("containerd service must use KillMode=process to preserve sandbox shims during restart")
	}
	pid, err := strconv.Atoi(props["MainPID"])
	if err != nil || pid <= 0 || props["ActiveState"] != "active" {
		if recovering && i.containerdExecutable != "" {
			return validateRecoveryExecStart(props["ExecStart"], i.containerdExecutable, i.cfg.ContainerdConfig, i.containerdInvocation)
		}
		return fmt.Errorf("containerd service is not active with a main PID")
	}
	cmdline, err := os.ReadFile(filepath.Join(i.procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return fmt.Errorf("reading live containerd argv: %w", err)
	}
	args := strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
	if len(args) == 0 || !filepath.IsAbs(args[0]) || filepath.Base(args[0]) != "containerd" {
		return fmt.Errorf("service must directly execute containerd")
	}
	configured, err := configFlagFromArgs(args)
	if err != nil {
		return err
	}
	if configured == "" {
		configured = containerdConfigPath
	}
	if configured != i.cfg.ContainerdConfig {
		return fmt.Errorf("live containerd config %q differs from selected config %q", configured, i.cfg.ContainerdConfig)
	}
	executable, err := os.Readlink(filepath.Join(i.procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return fmt.Errorf("reading live containerd executable: %w", err)
	}
	if !filepath.IsAbs(executable) || filepath.Base(executable) != "containerd" || strings.ContainsAny(executable, " \t\n") {
		return fmt.Errorf("unsupported live containerd executable %q", executable)
	}
	if i.containerdExecutable != "" && i.containerdExecutable != executable {
		return fmt.Errorf("containerd executable differs from persistent identity")
	}
	invocation := strings.Join(args, "\x00")
	if i.containerdInvocation != "" && i.containerdInvocation != invocation {
		return fmt.Errorf("live containerd invocation differs from persistent target identity")
	}
	if err := validateRecoveryExecStart(props["ExecStart"], executable, i.cfg.ContainerdConfig, invocation); err != nil {
		return err
	}
	// A pending journal already identifies the only target that can be repaired.
	// CRI may be down because containerd rejected the interrupted configuration.
	if err := i.cri.VerifyIdentity(ctx, pid, i.cfg.PodUID); err != nil {
		if recovering && i.containerdExecutable != "" && errors.Is(err, errCRIUnavailable) {
			return nil
		}
		return fmt.Errorf("selected CRI endpoint is not this pod's systemd containerd: %w", err)
	}
	st, err := i.cri.Status(ctx, true)
	if err != nil {
		if recovering && i.containerdExecutable != "" && errors.Is(err, errCRIUnavailable) {
			return nil
		}
		return err
	}
	if len(st.Handlers) == 0 {
		return errNoRuntimeHandlers
	}
	i.containerdExecutable = executable
	i.containerdInvocation = invocation
	return nil
}

func (i *Installer) configDump(ctx context.Context) ([]byte, error) {
	if i.containerdExecutable == "" {
		return nil, fmt.Errorf("containerd executable has not been validated")
	}
	return i.host.Run(ctx, i.containerdExecutable, "--config", i.cfg.ContainerdConfig, "config", "dump")
}

func parseProperties(out []byte) map[string]string {
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	return props
}

func configFlagFromArgs(args []string) (string, error) {
	result := ""
	for n := 1; n < len(args); n++ {
		arg := args[n]
		value := ""
		switch {
		case arg == "-c" || arg == "--config":
			n++
			if n >= len(args) {
				return "", fmt.Errorf("missing containerd config argument")
			}
			value = args[n]
		case strings.HasPrefix(arg, "--config="):
			value = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-c="):
			value = strings.TrimPrefix(arg, "-c=")
		case strings.HasPrefix(arg, "-c"):
			return "", fmt.Errorf("unsupported containerd config flag %q", arg)
		}
		if value != "" {
			if result != "" {
				return "", fmt.Errorf("duplicate containerd config flags")
			}
			result = value
		}
	}
	return result, nil
}

// ExecStart is accepted only for a direct, unambiguous invocation. In stopped
// service recovery it is checked against the previously validated executable.
func validateRecoveryExecStart(value, executable, config, invocation string) error {
	prefix, rest, ok := strings.Cut(value, " ; argv[]=")
	binary, direct := strings.CutPrefix(prefix, "{ path=")
	argv, _, haveArgs := strings.Cut(rest, " ; ")
	if !ok || !direct || !haveArgs || binary != executable || strings.ContainsAny(binary, " \t\n\\\"'$;{}") {
		return fmt.Errorf("systemd ExecStart must directly invoke the validated containerd executable")
	}
	args := strings.Fields(argv)
	if len(args) == 0 || args[0] != binary || strings.ContainsAny(argv, "\\\"'$;{}") {
		return fmt.Errorf("unsupported systemd containerd arguments")
	}
	if strings.Join(args, "\x00") != invocation {
		return fmt.Errorf("systemd ExecStart invocation differs from validated live containerd invocation")
	}
	configured, err := configFlagFromArgs(args)
	if err != nil {
		return err
	}
	if configured == "" {
		configured = containerdConfigPath
	}
	if configured != config {
		return fmt.Errorf("systemd ExecStart targets config %q, expected %q", configured, config)
	}
	for n := 1; n < len(args); n++ {
		arg := args[n]
		switch {
		case arg == "-c" || arg == "--config" || arg == "--address" || arg == "-a" || arg == "--root" || arg == "--state" || arg == "--log-level":
			n++
			if n >= len(args) {
				return fmt.Errorf("missing containerd argument")
			}
		case strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-c=") || strings.HasPrefix(arg, "--address=") || strings.HasPrefix(arg, "--root=") || strings.HasPrefix(arg, "--state=") || strings.HasPrefix(arg, "--log-level="):
		default:
			return fmt.Errorf("unsupported systemd containerd argument %q", arg)
		}
	}
	return nil
}
