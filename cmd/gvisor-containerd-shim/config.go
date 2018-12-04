/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import "github.com/BurntSushi/toml"

// config is the configuration for gvisor containerd shim.
type config struct {
	// RuncShim is the shim binary path for standard containerd-shim for runc.
	// When the runtime is `runc`, gvisor containerd shim will exec current
	// process to standard containerd-shim. This is a work around for containerd
	// 1.1. In containerd 1.2, containerd will choose different containerd-shims
	// based on runtime.
	RuncShim string `toml:"runc_shim"`
	// RunscConfig is configuration for runsc. The key value will be converted
	// to runsc flags --key=value directly.
	RunscConfig map[string]string `toml:"runsc_config"`
}

// loadConfig load gvisor containerd shim config from config file.
func loadConfig(path string) (*config, error) {
	var c config
	_, err := toml.DecodeFile(path, &c)
	if err != nil {
		return &c, err
	}
	return &c, nil
}
