// Copyright 2025 The gVisor Authors.
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

package nftables

import (
	"fmt"
	"os/exec"
)

// createDropAllTable creates a table, chain, and rule that drops all packets
// for the given family.
func createDropAllTable(ipv6 bool, tabName string) error {
	family := "ip"
	if ipv6 {
		family = "ip6"
	}
	tableArgs := []string{family, tabName}
	chainArgs := []string{family, tabName, "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"}
	ruleArgs := []string{family, tabName, "input", "drop"}

	if err := tableCmd("add", tableArgs); err != nil {
		return err
	}

	if err := chainCmd("add", chainArgs); err != nil {
		return err
	}

	return ruleCmd("add", ruleArgs)
}

func nftCmd(args []string) error {
	binary := "nft"
	cmd := exec.Command(binary, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error running nft with args %v\nerror: %v\noutput: %s", args, err, string(out))
	}
	return nil
}

func tableCmd(cmd string, args []string) error {
	return nftCmd(append([]string{cmd, "table"}, args...))
}

func chainCmd(cmd string, args []string) error {
	return nftCmd(append([]string{cmd, "chain"}, args...))
}

func ruleCmd(cmd string, args []string) error {
	return nftCmd(append([]string{cmd, "rule"}, args...))
}
