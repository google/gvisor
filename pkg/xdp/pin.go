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

package xdp

import "path/filepath"

// bpffsDirName is the path at which BPFFS is expected to be mounted.
const bpffsDirPath = "/sys/fs/bpf/"

// RedirectPinDir returns the directory to which eBPF objects will be pinned
// when xdp_loader is run against iface.
func RedirectPinDir(iface string) string {
	return filepath.Join(bpffsDirPath, iface)
}

// RedirectMapPath returns the path where the eBPF map will be pinned when
// xdp_loader is run against iface.
func RedirectMapPath(iface string) string {
	return filepath.Join(RedirectPinDir(iface), "redirect_ip_map")
}

// RedirectProgramPath returns the path where the eBPF program will be pinned
// when xdp_loader is run against iface.
func RedirectProgramPath(iface string) string {
	return filepath.Join(RedirectPinDir(iface), "redirect_program")
}

// RedirectLinkPath returns the path where the eBPF link will be pinned when
// xdp_loader is run against iface.
func RedirectLinkPath(iface string) string {
	return filepath.Join(RedirectPinDir(iface), "redirect_link")
}

// TunnelPinDir returns the directory to which eBPF objects will be pinned when
// xdp_loader is run against iface.
func TunnelPinDir(iface string) string {
	return filepath.Join(bpffsDirPath, iface)
}

// TunnelHostMapPath returns the path where the eBPF map will be pinned when
// xdp_loader is run against iface.
func TunnelHostMapPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_host_map")
}

// TunnelHostProgramPath returns the path where the eBPF program will be pinned
// when xdp_loader is run against iface.
func TunnelHostProgramPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_host_program")
}

// TunnelHostLinkPath returns the path where the eBPF link will be pinned when
// xdp_loader is run against iface.
func TunnelHostLinkPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_host_link")
}

// TunnelVethMapPath returns the path where the eBPF map should be pinned when
// xdp_loader is run against iface.
func TunnelVethMapPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_veth_map")
}

// TunnelVethProgramPath returns the path where the eBPF program should be pinned
// when xdp_loader is run against iface.
func TunnelVethProgramPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_veth_program")
}

// TunnelVethLinkPath returns the path where the eBPF link should be pinned when
// xdp_loader is run against iface.
func TunnelVethLinkPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_veth_link")
}
