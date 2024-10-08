// Copyright 2024 The gVisor Authors.
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

// Package hostsettings provides suggestions or adjustments for host kernel
// settings to improve runsc performance, stability, or security.
package hostsettings

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
)

// Handle deals with host settings according to the given policy.
func Handle(conf *config.Config) error {
	switch conf.HostSettings {
	case config.HostSettingsIgnore:
		return nil
	case config.HostSettingsCheck, config.HostSettingsCheckMandatory:
		deltas, errs := check(conf)
		for _, err := range errs {
			log.Warningf("Checking host settings: error: %v", err)
		}
		for _, delta := range deltas {
			if delta.Mandatory {
				return fmt.Errorf("host setting %q (currently: %q) is not supported (%s); must change it to %q for runsc to work", delta.Name, delta.FromValue, delta.Purpose, delta.ToValue)
			}
			if conf.HostSettings == config.HostSettingsCheck {
				log.Warningf("Host setting %q (currently: %q) is not optimal (%s); it is recommended to change it to %q", delta.Name, delta.FromValue, delta.Purpose, delta.ToValue)
			}
		}
	case config.HostSettingsAdjust, config.HostSettingsEnforce:
		deltas, errs := check(conf)
		for _, err := range errs {
			log.Warningf("Host settings: error: %v", err)
		}
		for _, delta := range deltas {
			log.Warningf("Host setting %q (currently: %q) is not optimal (%s); attempting to change it to %q...", delta.Name, delta.FromValue, delta.Purpose, delta.ToValue)
			err := delta.Apply()
			// We handle the nil error case first here as it simplifies control flow.
			if err == nil {
				log.Warningf("Host setting %q changed from %q to %q (%s)", delta.Name, delta.FromValue, delta.ToValue, delta.Purpose)
				continue
			}
			if delta.Mandatory {
				return fmt.Errorf("host setting %q (currently: %q) is not supported (%s), and trying to change it to %q failed (%w); bailing out as this is necessary for runsc to work", delta.Name, delta.FromValue, delta.Purpose, delta.ToValue, err)
			}
			if conf.HostSettings == config.HostSettingsEnforce {
				return fmt.Errorf("failed to adjust %s to %q: %w", delta.Name, delta.ToValue, err)
			}
			log.Warningf("Host settings: failed to adjust %s to %q: %v; continuing anyway.", delta.Name, delta.ToValue, err)
		}
	default:
		return fmt.Errorf("invalid host settings policy %d", conf.HostSettings)
	}
	return nil
}

// Setting is a host setting to check or adjust.
type Setting interface {
	// Name is the name of the setting. In most cases this should be the
	// full path of the setting, either under /sys or /proc/sys.
	// This can be a non-path for settings that are not controlled via files,
	// such as kernel command-line parameters or SELinux labels.
	Name() string

	// Delta checks whether the current value of the setting is optimal.
	// If already optimal, it returns a nil Delta.
	Delta() (*Delta, error)
}

// Delta is a change to make to a host setting.
type Delta struct {
	// Name of the setting being changed.
	Name string

	// FromValue is the value of the setting before applying the delta.
	FromValue string

	// ToValue is the value of the setting after applying the delta.
	ToValue string

	// Mandatory indicates whether the delta *must* be applied.
	// This should be set in cases where `runsc` will fail completely
	// if the delta is not applied.
	Mandatory bool

	// Purpose achieved by applying the delta.
	Purpose string

	// Apply applies the delta.
	Apply func() error
}

// pathSetting implements `Setting` for kernel settings controlled via files.
type pathSetting struct {
	// path is the full path of the setting, either under /sys or /proc/sys.
	path string

	// mightNotExist indicates that the file may not exist on all systems.
	// If the path does not exist, no delta is returned for this setting.
	mightNotExist bool

	// mightLackReadPerm indicates that the file may not be readable.
	// If the file cannot be read with a permission error, and we are running
	// in rootless mode, a message is logged but no delta is returned for this
	// setting.
	mightLackReadPerm bool

	// purpose describes the intent behind setting this value.
	purpose string

	// `delta` returns an empty string if the current value is optimal,
	// or a value to write to `path` if not optimal.
	// It also returns whether the delta is mandatory.
	delta func(conf *config.Config, current string) (string, bool, error)
}

// Name implements `Setting.Name`.
func (s pathSetting) Name() string {
	return s.path
}

// Delta implements `Setting.Delta`.
func (s pathSetting) Delta(conf *config.Config) (*Delta, error) {
	currentBytes, err := os.ReadFile(s.path)
	if err != nil {
		if s.mightNotExist && os.IsNotExist(err) {
			return nil, nil
		}
		if s.mightLackReadPerm && os.IsPermission(err) {
			log.Infof("Host settings: Cannot check if %q is optimal (%s): %v; continuing anyway.", s.path, s.purpose, err)
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read %q: %w", s.path, err)
	}
	currentValue := strings.TrimSpace(string(currentBytes))
	newValue, mandatory, err := s.delta(conf, currentValue)
	if err != nil {
		return nil, err
	}
	if newValue == "" {
		return nil, nil
	}
	return &Delta{
		Name:      s.path,
		FromValue: currentValue,
		ToValue:   newValue,
		Mandatory: mandatory,
		Purpose:   s.purpose,
		Apply: func() error {
			if err := os.WriteFile(s.path, []byte(newValue), 0644); err != nil {
				return fmt.Errorf("cannot write %q: %w", s.path, err)
			}
			// Double-check that the value has been written properly.
			newDelta, err := s.Delta(conf)
			if err != nil {
				return fmt.Errorf("cannot re-read %q after writing: %w", s.path, err)
			}
			if newDelta != nil {
				return fmt.Errorf("writing to %q did not change the observed value: wrote %q but read back %q", s.path, newValue, newDelta.FromValue)
			}
			return nil
		},
	}, nil
}

// checks checks the host settings and returns any deltas to do or errors
// occurred while checking.
func check(conf *config.Config) ([]*Delta, []error) {
	log.Debugf("Checking host settings")
	settings := []pathSetting{
		{
			path:    "/sys/kernel/mm/transparent_hugepage/shmem_enabled",
			purpose: "turning on transparent hugepages support in shmem increases memory allocation performance",
			delta: func(conf *config.Config, current string) (string, bool, error) {
				// /sys/kernel/mm/transparent_hugepage/shmem_enabled is formatted like:
				// `always within_size advise [never] deny force`.
				if strings.Contains(current, "[always]") || strings.Contains(current, "[advise]") || strings.Contains(current, "[force]") || strings.Contains(current, "[within_size]") {
					return "", false, nil
				}
				return "advise", false, nil
			},
		},
		{
			path:    "/proc/sys/vm/max_map_count",
			purpose: "increasing max_map_count decreases the likelihood of host VMA exhaustion",
			delta: func(conf *config.Config, current string) (string, bool, error) {
				const recommendedMaxMapCount = 4194304
				currentVal, err := strconv.Atoi(strings.TrimSpace(current))
				if err != nil {
					return "", false, fmt.Errorf("failed to parse %q as an integer: %v", current, err)
				}
				if currentVal >= recommendedMaxMapCount {
					return "", false, nil
				}
				return strconv.Itoa(recommendedMaxMapCount), false, nil
			},
		},
		{
			path:    "/proc/sys/user/max_user_namespaces",
			purpose: "runsc requires creating at least 2 new user namespaces and may run into the limit when creating multiple containers",
			delta: func(conf *config.Config, current string) (string, bool, error) {
				const recommendedMaxUserNamespaces = 256
				currentVal, err := strconv.Atoi(strings.TrimSpace(current))
				if err != nil {
					return "", false, fmt.Errorf("failed to parse %q as an integer: %v", current, err)
				}
				if currentVal >= recommendedMaxUserNamespaces {
					return "", false, nil
				}
				if currentVal < 2 {
					// If less than two, runsc will definitely fail (it needs one for
					// the gofer and one for the sandbox), so mark as mandatory.
					return strconv.Itoa(recommendedMaxUserNamespaces), true, nil
				}
				return strconv.Itoa(recommendedMaxUserNamespaces), false, nil
			},
		},
		{
			path:          "/proc/sys/kernel/unprivileged_userns_clone",
			mightNotExist: true,
			purpose:       "in rootless mode, runsc requires the ability to create new user namespaces without privileges",
			delta: func(conf *config.Config, current string) (string, bool, error) {
				if !conf.Rootless {
					// Setting not required.
					return "", false, nil
				}
				currentVal, err := strconv.Atoi(strings.TrimSpace(current))
				if err != nil {
					return "", false, fmt.Errorf("failed to parse %q as an integer: %v", current, err)
				}
				if currentVal != 0 {
					return "", false, nil
				}
				return "1", true, nil
			},
		},
		{
			path:              "/proc/sys/kernel/unprivileged_userns_apparmor_policy",
			mightNotExist:     true,
			mightLackReadPerm: true,
			purpose:           "in rootless mode, runsc requires the ability to create new user namespaces without privileges",
			delta: func(conf *config.Config, current string) (string, bool, error) {
				if !conf.Rootless {
					// Setting not required.
					return "", false, nil
				}
				currentVal, err := strconv.Atoi(strings.TrimSpace(current))
				if err != nil {
					return "", false, fmt.Errorf("failed to parse %q as an integer: %v", current, err)
				}
				if currentVal != 0 {
					return "", false, nil
				}
				return "1", true, nil
			},
		},
	}
	var deltas []*Delta
	var errs []error
	for _, setting := range settings {
		log.Debugf("Checking host setting: %s", setting.Name())
		delta, err := setting.Delta(conf)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to check %s: %v", setting.Name(), err))
			continue
		}
		if delta != nil {
			deltas = append(deltas, delta)
		}
	}
	return deltas, errs
}
