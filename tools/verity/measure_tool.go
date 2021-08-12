// Copyright 2021 The gVisor Authors.
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

// This binary can be used to run a measurement of the verity file system,
// generate the corresponding Merkle tree files, and return the root hash.
package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

var path = flag.String("path", "", "path to the verity file system.")
var rawpath = flag.String("rawpath", "", "path to the raw file system.")

const maxDigestSize = 64

type digest struct {
	metadata linux.DigestMetadata
	digest   [maxDigestSize]byte
}

func main() {
	flag.Parse()
	if *path == "" {
		log.Fatalf("no path provided")
	}
	if *rawpath == "" {
		log.Fatalf("no rawpath provided")
	}
	// TODO(b/182315468): Optimize the Merkle tree generate process to
	// allow only updating certain files/directories.
	if err := clearMerkle(*rawpath); err != nil {
		log.Fatalf("Failed to clear merkle files in %s: %v", *rawpath, err)
	}
	if err := enableDir(*path); err != nil {
		log.Fatalf("Failed to enable file system %s: %v", *path, err)
	}
	// Print the root hash of the file system to stdout.
	if err := measure(*path); err != nil {
		log.Fatalf("Failed to measure file system %s: %v", *path, err)
	}
}

func clearMerkle(path string) error {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			if err := clearMerkle(path + "/" + file.Name()); err != nil {
				return err
			}
		} else if strings.HasPrefix(file.Name(), ".merkle.verity") {
			if err := os.Remove(path + "/" + file.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

// enableDir enables verity features on all the files and sub-directories within
// path.
func enableDir(path string) error {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.IsDir() {
			// For directories, first enable its children.
			if err := enableDir(path + "/" + file.Name()); err != nil {
				return err
			}
		} else if file.Mode().IsRegular() {
			// For regular files, open and enable verity feature.
			f, err := os.Open(path + "/" + file.Name())
			if err != nil {
				return err
			}
			var p uintptr
			if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), uintptr(linux.FS_IOC_ENABLE_VERITY), p); err != 0 {
				return err
			}
		}
	}
	// Once all children are enabled, enable the parent directory.
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	var p uintptr
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), uintptr(linux.FS_IOC_ENABLE_VERITY), p); err != 0 {
		return err
	}
	return nil
}
