// Copyright 2022 The gVisor Authors.
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

// Package tracereplay implements a tool that can save and replay messages
// issued from remote.Remote.
package tracereplay

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const signature = "tracereplay file"

func writeSize(w io.Writer, val int) error {
	var bin [8]byte
	binary.LittleEndian.PutUint64(bin[:], uint64(val))
	_, err := w.Write(bin[:])
	return err
}

func readSize(r io.Reader) (int, error) {
	var bin [8]byte
	if read, err := r.Read(bin[:]); err != nil {
		return 0, err
	} else if read != 8 {
		return 0, fmt.Errorf("truncated read (%d bytes)", read)
	}
	size := int(binary.LittleEndian.Uint64(bin[:]))
	// Prevent returning a too large size to avoid OOMs.
	if size > 1024*1024 {
		return 0, fmt.Errorf("size is too big: %d", size)
	}
	return size, nil
}

func writeWithSize(f *os.File, buf []byte) error {
	if err := writeSize(f, len(buf)); err != nil {
		return err
	}
	_, err := f.Write(buf)
	return err
}

func readWithSize(r io.Reader) ([]byte, error) {
	size, err := readSize(r)
	if err != nil {
		return nil, err
	}
	bytes := make([]byte, size)
	if err := readFull(r, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

func readFull(r io.Reader, dest []byte) error {
	if read, err := r.Read(dest); err != nil {
		return err
	} else if read < len(dest) {
		return fmt.Errorf("truncated read. Read %d bytes, expected %d bytes", read, len(dest))
	}
	return nil
}

// Config contains information required to replay messages from a file.
type Config struct {
	// Version is the wire format saved in the file.
	Version uint32 `json:"version"`
}
