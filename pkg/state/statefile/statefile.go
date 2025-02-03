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

// Package statefile defines the state file data stream.
//
// This package currently does not include any details regarding the state
// encoding itself, only details regarding state metadata and data layout.
//
// The file format is defined as follows.
//
// /------------------------------------------------------\
// |                   header (8-bytes)                   |
// +------------------------------------------------------+
// |              metadata length (8-bytes)               |
// +------------------------------------------------------+
// |                       metadata                       |
// +------------------------------------------------------+
// |                         data                         |
// \------------------------------------------------------/
//
// First, it includes a 8-byte magic header which is the following
// sequence of bytes [0x67, 0x56, 0x69, 0x73, 0x6f, 0x72, 0x53, 0x46]
//
// This header is followed by an 8-byte length N (big endian), and an
// ASCII-encoded JSON map that is exactly N bytes long.
//
// This map includes only strings for keys and strings for values. Keys in the
// map that begin with "_" are for internal use only. They may be read, but may
// not be provided by the user. In the future, this metadata may contain some
// information relating to the state encoding itself.
//
// After the map, the remainder of the file is the state data.
package statefile

import (
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/compressio"
)

// keySize is the AES-256 key length.
const keySize = 32

// stateFileChunkSize is the chunk size used to read/write the state file.
const stateFileChunkSize = 2 * 1024 * 1024

// maxMetadataSize is the size limit of metadata section.
const maxMetadataSize = 16 * 1024 * 1024

// magicHeader is the byte sequence beginning each file.
var magicHeader = []byte("\x67\x56\x69\x73\x6f\x72\x53\x46")

// ErrBadMagic is returned if the header does not match.
var ErrBadMagic = fmt.Errorf("bad magic header")

// ErrMetadataMissing is returned if the state file is missing mandatory metadata.
var ErrMetadataMissing = fmt.Errorf("missing metadata")

// ErrInvalidMetadataLength is returned if the metadata length is too large.
var ErrInvalidMetadataLength = fmt.Errorf("metadata length invalid, maximum size is %d", maxMetadataSize)

// ErrMetadataInvalid is returned if passed metadata is invalid.
var ErrMetadataInvalid = fmt.Errorf("metadata invalid, can't start with _")

// ErrInvalidFlags is returned if passed flags set is invalid.
var ErrInvalidFlags = fmt.Errorf("flags set is invalid")

const (
	// CompressionKey is the key for the compression level in the metadata.
	CompressionKey = "compression"
)

// CompressionLevel is the image compression level.
type CompressionLevel string

const (
	// CompressionLevelFlateBestSpeed represents flate algorithm in best-speed mode.
	CompressionLevelFlateBestSpeed = CompressionLevel("flate-best-speed")
	// CompressionLevelNone represents the absence of any compression on an image.
	CompressionLevelNone = CompressionLevel("none")
	// CompressionLevelDefault represents the default compression level.
	CompressionLevelDefault = CompressionLevelFlateBestSpeed
)

func (c CompressionLevel) String() string {
	return string(c)
}

// Options is statefile options.
type Options struct {
	// Compression is an image compression type/level.
	Compression CompressionLevel

	// Resume indicates if the sandbox process should continue running
	// after checkpointing.
	Resume bool
}

// WriteToMetadata save options to the metadata storage.  Method returns the
// reference to the original metadata map to allow to be used in the chain calls.
func (o Options) WriteToMetadata(metadata map[string]string) map[string]string {
	metadata[CompressionKey] = string(o.Compression)
	return metadata
}

// CompressionLevelFromString parses a string into the CompressionLevel.
func CompressionLevelFromString(val string) (CompressionLevel, error) {
	switch val {
	case string(CompressionLevelFlateBestSpeed):
		return CompressionLevelFlateBestSpeed, nil
	case string(CompressionLevelNone):
		return CompressionLevelNone, nil
	case "":
		return CompressionLevelDefault, nil
	default:
		return CompressionLevelNone, ErrInvalidFlags
	}
}

// CompressionLevelFromMetadata returns image compression type stored in the metadata.
// If the metadata doesn't contain compression information the default behavior
// is the "flate-best-speed" state because the default behavior used to be to always
// compress. If the parameter is missing it will be set to default.
func CompressionLevelFromMetadata(metadata map[string]string) (CompressionLevel, error) {
	compression := CompressionLevelDefault

	if val, ok := metadata[CompressionKey]; ok {
		var err error
		if compression, err = CompressionLevelFromString(val); err != nil {
			return CompressionLevelNone, err
		}
	} else {
		metadata[CompressionKey] = string(compression)
	}

	return compression, nil
}

func writeMetadataLen(w io.Writer, val uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)
	_, err := w.Write(buf[:])
	return err
}

// NewWriter returns a state data writer for a statefile.
//
// Note that the returned WriteCloser must be closed.
func NewWriter(w io.Writer, key []byte, metadata map[string]string) (io.WriteCloser, error) {
	if metadata == nil {
		metadata = make(map[string]string)
	}
	for k := range metadata {
		if strings.HasPrefix(k, "_") {
			return nil, ErrMetadataInvalid
		}
	}

	// Create our HMAC function.
	h := hmac.New(sha256.New, key)
	mw := io.MultiWriter(w, h)

	// First, write the header.
	if _, err := mw.Write(magicHeader); err != nil {
		return nil, err
	}

	// Generate a timestamp, for convenience only.
	metadata["_timestamp"] = time.Now().UTC().String()
	defer delete(metadata, "_timestamp")

	// Save compression state
	compression, err := CompressionLevelFromMetadata(metadata)
	if err != nil {
		return nil, err
	}

	// Write the metadata.
	b, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	if len(b) > maxMetadataSize {
		return nil, ErrInvalidMetadataLength
	}

	// Metadata length.
	if err := writeMetadataLen(mw, uint64(len(b))); err != nil {
		return nil, err
	}
	// Metadata bytes; io.MultiWriter will return a short write error if
	// any of the writers returns < n.
	if _, err := mw.Write(b); err != nil {
		return nil, err
	}
	// Write the current hash.
	cur := h.Sum(nil)
	for done := 0; done < len(cur); {
		n, err := mw.Write(cur[done:])
		done += n
		if err != nil {
			return nil, err
		}
	}

	// Wrap in compression. When using "best compression" mode, there is usually
	// only a little gain in file size reduction, which translate to even smaller
	// gain in restore latency reduction, while incurring much more CPU usage at
	// save time.
	if compression == CompressionLevelFlateBestSpeed {
		return compressio.NewWriter(w, key, stateFileChunkSize, flate.BestSpeed)
	}

	return compressio.NewSimpleWriter(w, key, stateFileChunkSize), nil
}

// MetadataUnsafe reads out the metadata from a state file without verifying any
// HMAC. This function shouldn't be called for untrusted input files.
func MetadataUnsafe(r io.Reader) (map[string]string, error) {
	return metadata(r, nil)
}

func readMetadataLen(r io.Reader) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

// metadata validates the magic header and reads out the metadata from a state
// data stream.
func metadata(r io.Reader, h hash.Hash) (map[string]string, error) {
	if h != nil {
		r = io.TeeReader(r, h)
	}

	// Read and validate magic header.
	b := make([]byte, len(magicHeader))
	if _, err := r.Read(b); err != nil {
		return nil, err
	}
	if !bytes.Equal(b, magicHeader) {
		return nil, ErrBadMagic
	}

	// Read and validate metadata.
	b, err := func() (b []byte, err error) {
		defer func() {
			if r := recover(); r != nil {
				b = nil
				err = fmt.Errorf("%v", r)
			}
		}()

		metadataLen, err := readMetadataLen(r)
		if err != nil {
			return nil, err
		}
		if metadataLen > maxMetadataSize {
			return nil, ErrInvalidMetadataLength
		}
		b = make([]byte, int(metadataLen))
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		return b, nil
	}()
	if err != nil {
		return nil, err
	}

	if h != nil {
		// Check the hash prior to decoding.
		cur := h.Sum(nil)
		buf := make([]byte, len(cur))
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		if !hmac.Equal(cur, buf) {
			return nil, compressio.ErrHashMismatch
		}
	}

	// Decode the metadata.
	metadata := make(map[string]string)
	if err := json.Unmarshal(b, &metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

// NewReader returns a reader for a statefile.
func NewReader(r io.Reader, key []byte) (io.Reader, map[string]string, error) {
	// Read the metadata with the hash.
	h := hmac.New(sha256.New, key)
	metadata, err := metadata(r, h)
	if err != nil {
		return nil, nil, err
	}

	// Determine image compression state. If the metadata doesn't contain
	// compression information the default behavior is the "compressed" state
	// because the default behavior used to be to always compress.
	compression, err := CompressionLevelFromMetadata(metadata)
	if err != nil {
		return nil, nil, err
	}

	// Pick correct reader
	var cr io.Reader

	if compression == CompressionLevelFlateBestSpeed {
		cr, err = compressio.NewReader(r, key)
	} else if compression == CompressionLevelNone {
		cr = compressio.NewSimpleReader(r, key)
	} else {
		// Should never occur, as it has the default path.
		return nil, nil, fmt.Errorf("metadata contains invalid compression flag value: %v", compression)
	}

	if err != nil {
		return nil, nil, err
	}

	return cr, metadata, nil
}
