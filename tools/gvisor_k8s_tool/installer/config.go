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

// Package installer installs an image-bundled gVisor release on a Kubernetes node.
package installer

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const containerdConfigPath = "/etc/containerd/config.toml"
const hostLockPath = "/run/gvisor-installer.lock"

// Config describes one node and its immutable containerd target.
type Config struct {
	NodeName          string
	Namespace         string
	PodName           string
	PodUID            string
	Version           string
	Handler           string
	InstallDir        string
	StateDir          string
	HostRoot          string
	PayloadDir        string
	ContainerdConfig  string
	ContainerdSocket  string
	ContainerdService string
	RunscConfigSrc    string
	HealthAddr        string
	ReconcileInterval time.Duration
	RetryInterval     time.Duration
	ReconcileTimeout  time.Duration
}

var handlerRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ConfigFromEnv reads the DaemonSet configuration.
func ConfigFromEnv() (Config, error) {
	get := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback
	}
	cfg := Config{
		NodeName:          os.Getenv("NODE_NAME"),
		Namespace:         os.Getenv("POD_NAMESPACE"),
		PodName:           os.Getenv("POD_NAME"),
		PodUID:            os.Getenv("POD_UID"),
		Handler:           get("GVISOR_HANDLER", "runsc"),
		InstallDir:        get("INSTALL_DIR", "/opt/gvisor"),
		StateDir:          "/var/lib/gvisor-installer",
		HostRoot:          "/host",
		PayloadDir:        "/opt/gvisor/release",
		ContainerdConfig:  get("CONTAINERD_CONFIG", containerdConfigPath),
		ContainerdSocket:  get("CONTAINERD_SOCKET", "/run/containerd/containerd.sock"),
		ContainerdService: get("CONTAINERD_SERVICE", "containerd"),
		RunscConfigSrc:    "/etc/gvisor-installer/runsc.toml",
		HealthAddr:        ":8093",
		ReconcileInterval: 5 * time.Minute,
		RetryInterval:     time.Minute,
		ReconcileTimeout:  defaultReconcileTimeout,
	}
	for name, dest := range map[string]*time.Duration{"RECONCILE_INTERVAL": &cfg.ReconcileInterval, "RETRY_INTERVAL": &cfg.RetryInterval, "RECONCILE_TIMEOUT": &cfg.ReconcileTimeout} {
		if value := os.Getenv(name); value != "" {
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				return cfg, fmt.Errorf("%s must be a positive duration", name)
			}
			*dest = d
		}
	}
	return cfg, cfg.Validate()
}

// Validate rejects ambiguous host paths and unsupported handler names.
func (c Config) Validate() error {
	if c.NodeName == "" || c.PodUID == "" || c.PodName == "" || c.Namespace == "" {
		return fmt.Errorf("NODE_NAME, POD_NAME, POD_NAMESPACE and POD_UID are required")
	}
	if !handlerRe.MatchString(c.Handler) || len(c.Handler) > 63 {
		return fmt.Errorf("GVISOR_HANDLER must be a DNS label")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_.@-]+$`).MatchString(c.ContainerdService) || strings.HasPrefix(c.ContainerdService, "-") {
		return fmt.Errorf("invalid CONTAINERD_SERVICE")
	}
	for name, value := range map[string]string{"INSTALL_DIR": c.InstallDir, "STATE_DIR": c.StateDir, "CONTAINERD_CONFIG": c.ContainerdConfig, "CONTAINERD_SOCKET": c.ContainerdSocket, "HostRoot": c.HostRoot, "PayloadDir": c.PayloadDir} {
		if !path.IsAbs(value) || path.Clean(value) != value || value == "/" || strings.ContainsAny(value, "\x00\n\r") {
			return fmt.Errorf("%s must be a clean absolute path", name)
		}
	}
	return nil
}

func (c Config) hostPath(p string) string { return path.Join(c.HostRoot, p) }
func (c Config) CRISocketPath() string    { return c.hostPath(c.ContainerdSocket) }
func (c Config) releasesDir() string      { return path.Join(c.InstallDir, "releases") }
func (c Config) configsDir() string       { return path.Join(c.InstallDir, "runsc-configs") }
