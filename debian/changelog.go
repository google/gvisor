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

// Binary changelog writes the Debian changelog for a gVisor package version.
package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

// tools/tag_release.sh accepts release-YYYYMMDD.N, with the prefix removed
// from the Debian version. Other versions have no release date.
var releaseVersion = regexp.MustCompile(`^(20[0-9]{6})\.[0-9]+$`)

const changelog = `runsc (%s) unstable; urgency=medium

  * See https://gvisor.dev/docs/ for release details.

 -- The gVisor Authors <gvisor-dev@googlegroups.com>  %s
`

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: changelog VERSION OUTPUT")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	version := strings.TrimRight(string(raw), "\n")
	// Use the Unix epoch as the placeholder for an unreleased build.
	date := time.Unix(0, 0).UTC()
	if match := releaseVersion.FindStringSubmatch(version); match != nil {
		date, err = time.Parse("20060102", match[1])
		if err != nil {
			log.Fatalf("invalid release date in %q: %v", version, err)
		}
	}
	if err := os.WriteFile(os.Args[2], []byte(fmt.Sprintf(changelog, version, date.Format(time.RFC1123Z))), 0644); err != nil {
		log.Fatal(err)
	}
}
