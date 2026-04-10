// Copyright 2018 The gVisor Authors.
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

package cmd

import (
	"github.com/moby/sys/capability"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cmd/util"
)

// allCapTypes, applyCaps, getCaps, trimCaps, capsFromNames and capFromName
// delegate to their exported equivalents in runsc/cmd/util.

var allCapTypes = util.AllCapTypes

func applyCaps(caps *specs.LinuxCapabilities) error {
	return util.ApplyCaps(caps)
}

func getCaps(which capability.CapType, caps *specs.LinuxCapabilities) []string {
	return util.GetCaps(which, caps)
}

func trimCaps(names []string, setter capability.Capabilities) ([]capability.Cap, error) {
	return util.TrimCaps(names, setter)
}

func capsFromNames(names []string) ([]capability.Cap, error) {
	return util.CapsFromNames(names)
}

var capFromName = util.CapFromName
