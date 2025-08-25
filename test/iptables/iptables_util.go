// Copyright 2019 The gVisor Authors.
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

package iptables

import (
	"fmt"
	"os/exec"
)

// filterTable calls `ip{6}tables -t filter` with the given args.
func filterTable(ipv6 bool, args ...string) error {
	return tableCmd(ipv6, "filter", args)
}

// natTable calls `ip{6}tables -t nat` with the given args.
func natTable(ipv6 bool, args ...string) error {
	return tableCmd(ipv6, "nat", args)
}

func tableCmd(ipv6 bool, table string, args []string) error {
	args = append([]string{"-t", table}, args...)
	binary := "iptables-legacy"
	if ipv6 {
		binary = "ip6tables-legacy"
	}
	cmd := exec.Command(binary, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error running iptables with args %v\nerror: %v\noutput: %s", args, err, string(out))
	}
	return nil
}

// filterTableRules is like filterTable, but runs multiple iptables commands.
func filterTableRules(ipv6 bool, argsList [][]string) error {
	return tableRules(ipv6, "filter", argsList)
}

// natTableRules is like natTable, but runs multiple iptables commands.
func natTableRules(ipv6 bool, argsList [][]string) error {
	return tableRules(ipv6, "nat", argsList)
}

func tableRules(ipv6 bool, table string, argsList [][]string) error {
	for _, args := range argsList {
		if err := tableCmd(ipv6, table, args); err != nil {
			return err
		}
	}
	return nil
}
