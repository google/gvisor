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

// Package journal implements a metadata journal for a tmpfs whose file data
// is stored in a host-backed pgalloc.MemoryFile (the filestore). The journal
// lives in its own host file, next to the filestore. It records which
// filestore pages hold each file's data, letting a new sentry rebuild the
// tmpfs after the previous sentry crashed or stopped without copying file
// data.
//
// Offset 0 of the journal file holds a 4 KiB header, and two regions later in
// the file hold the journal records. The header holds the offset and size of
// each region, so that a region can move and grow when a snapshot does not
// fit. One region is active at a time. It holds a snapshot of the full tmpfs state, followed
// by records for later changes. The writer appends records through a shared
// mapping of the active region, so an append is a memory copy with no system
// calls. A sentry crash cannot lose appended records, since the host page
// cache keeps them. Host crashes are out of scope; the journal never calls
// fsync.
//
// Compaction writes a new snapshot to the inactive region, then makes it
// active with one atomic store to the header. Until that store, the old
// region stays valid, so a crash during compaction is safe. Before it writes
// the snapshot, compaction moves the inactive region to a larger range of the
// journal file if the snapshot may not fit. The inactive region is empty at
// that point, so nothing is copied.
//
// Replay treats the journal as untrusted: it stops at the first torn record
// and validates the resulting state strictly.
package journal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
)

// Header layout. All integers are little-endian.
//
//	0:    magic      [8]byte
//	8:    version    u32
//	12:   unused     u32
//	16:   regionSize u64
//	24:   active     u64 (generation | flag bits; updated atomically)
//	32:   buildID    u16 length + [maxIDLen]byte
//	32+2+maxIDLen: imageID u16 length + [maxIDLen]byte
//	headerSize-48: region 0 offset u64, size u64
//	headerSize-32: region 1 offset u64, size u64
//	headerSize-16: filestoreEnd u64 (updated atomically)
//	headerSize-4: crc32c u32 over the immutable fields: bytes [0, 24) and
//	              [32, headerSize-48)
//
// regionSize is the minimum size of a region. A region descriptor changes
// only while its region is inactive, so a torn descriptor is never used.
//
// filestoreEnd is a high-water mark in the filestore: it is at least the end
// of every extent in an EXTENT_SET record in the active region. Open refuses
// extents beyond it. The host can shrink the filestore to it before the
// sandbox starts; see FilestoreEnd.
const (
	headerSize      = 4096
	formatVersion   = 4
	maxIDLen        = 1024
	activeOff       = 24
	buildIDOff      = 32
	imageIDOff      = buildIDOff + 2 + maxIDLen
	regionDescOff   = headerSize - 48
	filestoreEndOff = headerSize - 16
	headerCRCOff    = headerSize - 4

	// The active generation selects the active region: slot = gen & 1.
	// brokenBit is set when a record could not be appended because the
	// active region was full; the next successful compaction clears it.
	brokenBit = uint64(1) << 63

	// incompleteBit is set in a new journal for a filestore that a restore
	// or tar archive populates. The first Commit clears it.
	incompleteBit = uint64(1) << 62

	activeFlags = brokenBit | incompleteBit
)

var headerMagic = [8]byte{'g', 'V', 't', 'm', 'p', 'J', 'n', 'l'}

// Region header layout:
//
//	0:  magic    u32
//	4:  unused   u32
//	8:  gen      u64
//	16: startSeq u64
//	24: crc32c   u32 over bytes [0, 24)
const (
	regionMagic      = 0x4e474552 // "REGN"
	regionHeaderSize = 64
)

const (
	// DefaultRegionSize is the default minimum size of a journal region.
	DefaultRegionSize = 64 << 20

	minRegionSize = 4 * hostarch.PageSize
	maxRegionSize = 1 << 32
)

// Options configures Create, CreateIncomplete, and Open.
type Options struct {
	// BuildID identifies the binary that writes the journal. Open refuses a
	// journal written by a different binary.
	BuildID string

	// ImageID optionally identifies the lower layer of the overlay. Recorded on
	// Create/CreateIncomplete; if non-empty on Open, Open refuses a journal
	// created with a different ImageID.
	ImageID string

	// RegionSize is the minimum size of each region. It is only used when
	// a new journal is created. If it is 0, DefaultRegionSize is used.
	RegionSize uint64

	// FilestoreSize bounds replayed extents if non-zero. Open also bounds
	// them by the current size of the MemoryFile's backing file.
	FilestoreSize uint64
}

// Journal is an open journal backed by a host file.
type Journal struct {
	// file is the journal file. file is immutable.
	file *os.File

	// header is a shared mapping of [0, headerSize) in file.
	header []byte

	mu sync.Mutex

	// regionMaps holds the shared mapping for each allocated region slot.
	//
	// +checklocks:mu
	regionMaps [2][]byte

	// closed is true after Close. Appends are dropped after Close.
	//
	// +checklocks:mu
	closed bool
}

// region describes a region of the journal in the backing file.
type region struct {
	off  uint64
	size uint64
}

func (r region) end() uint64 {
	return r.off + r.size
}

// valid returns true if r is a well-formed region in a file of size
// fileSize.
func (r region) valid(fileSize uint64) bool {
	return r.off >= headerSize && hostarch.IsPageAligned(r.off) &&
		r.size >= minRegionSize && r.size <= maxRegionSize && hostarch.IsPageAligned(r.size) &&
		r.off <= fileSize && r.size <= fileSize-r.off
}

// Create initializes a new journal in file, replacing any existing contents.
// On success, the returned Journal takes ownership of file.
func Create(file *os.File, opts Options) (*Journal, error) {
	return create(file, opts, false /* incomplete */)
}

// Open replays the journal in file and adopts the filestore pages that it
// references into mf, which must have been created with KeepFileContents.
//
// If keepJournal is true, Open also returns an open Journal that continues
// journaling into file, and that takes ownership of file. If keepJournal is
// false, Open returns a nil *Journal, and the caller keeps ownership of file.
//
// Open refuses an empty or uninitialized file (ErrIncomplete), a journal marked
// incomplete (ErrIncomplete) or broken, a journal with a mismatched format
// version or build ID, a journal whose image ID differs from a non-empty
// opts.ImageID, or one whose contents are invalid.
func Open(mf *pgalloc.MemoryFile, file *os.File, opts Options, keepJournal bool) (*Journal, *State, error) {
	if len(opts.BuildID) > maxIDLen || len(opts.ImageID) > maxIDLen {
		return nil, nil, fmt.Errorf("build ID or image ID longer than %d bytes", maxIDLen)
	}
	fd := int(file.Fd())
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, nil, fmt.Errorf("failed to stat journal: %w", err)
	}
	if stat.Size == 0 {
		return nil, nil, ErrIncomplete
	}
	if stat.Size < headerSize {
		return nil, nil, fmt.Errorf("journal size %d is smaller than its header", stat.Size)
	}
	journalSize := uint64(stat.Size)
	var hdr [headerSize]byte
	if _, err := unix.Pread(fd, hdr[:], 0); err != nil {
		return nil, nil, fmt.Errorf("failed to read journal header: %w", err)
	}
	// Initialization writes the magic last. A header without a magic was
	// never completely written.
	var zeroMagic [len(headerMagic)]byte
	if bytes.Equal(hdr[:len(headerMagic)], zeroMagic[:]) {
		return nil, nil, ErrIncomplete
	}

	_, err := checkHeader(hdr[:], opts)
	if err != nil {
		return nil, nil, err
	}
	active := binary.LittleEndian.Uint64(hdr[activeOff:])
	if active&incompleteBit != 0 {
		return nil, nil, ErrIncomplete
	}
	if active&brokenBit != 0 {
		return nil, nil, fmt.Errorf("journal overflowed before the previous sandbox stopped; its state is incomplete")
	}

	gen := active
	activeSlot := int(gen & 1)
	regions := [2]region{loadRegionFromHeader(hdr[:], 0), loadRegionFromHeader(hdr[:], 1)}
	r := regions[activeSlot]
	if !r.valid(journalSize) {
		return nil, nil, fmt.Errorf("active journal region [%#x, +%#x) is not valid in a %#x-byte file", r.off, r.size, journalSize)
	}

	activeMap, err := mmapRange(fd, r.off, r.size)
	if err != nil {
		return nil, nil, err
	}
	if _, err := checkRegionHeader(activeMap, gen); err != nil {
		unmapRange(activeMap)
		return nil, nil, err
	}
	st := &State{}

	if err := mf.AdoptExisting(st.UsedRanges(), usage.Tmpfs); err != nil {
		unmapRange(activeMap)
		return nil, nil, fmt.Errorf("failed to adopt filestore pages: %w", err)
	}

	if !keepJournal {
		unmapRange(activeMap)
		return nil, st, nil
	}

	headerMap, err := mmapRange(fd, 0, headerSize)
	if err != nil {
		unmapRange(activeMap)
		return nil, nil, err
	}
	j := &Journal{
		file:   file,
		header: headerMap,
	}
	j.mu.Lock()
	j.regionMaps[activeSlot] = activeMap
	j.mu.Unlock()
	return j, st, nil
}

// create initializes a new journal in file.
func create(file *os.File, opts Options, incomplete bool) (*Journal, error) {
	if len(opts.BuildID) > maxIDLen || len(opts.ImageID) > maxIDLen {
		return nil, fmt.Errorf("build ID or image ID longer than %d bytes", maxIDLen)
	}
	regionSize := opts.RegionSize
	if regionSize == 0 {
		regionSize = DefaultRegionSize
	}
	if regionSize < minRegionSize || regionSize > maxRegionSize || !hostarch.IsPageAligned(regionSize) {
		return nil, fmt.Errorf("invalid region size %d", regionSize)
	}

	// Truncate first so that the file holds no stale header or records.
	regions := [2]region{
		{off: headerSize, size: regionSize},
		{off: headerSize + regionSize, size: regionSize},
	}
	if err := file.Truncate(0); err != nil {
		return nil, fmt.Errorf("failed to truncate journal file: %w", err)
	}
	if err := file.Truncate(int64(regions[1].end())); err != nil {
		return nil, fmt.Errorf("failed to size journal file: %w", err)
	}
	fd := int(file.Fd())
	headerMap, err := mmapRange(fd, 0, headerSize)
	if err != nil {
		return nil, err
	}
	map0, err := mmapRange(fd, regions[0].off, regionSize)
	if err != nil {
		unmapRange(headerMap)
		return nil, err
	}
	map1, err := mmapRange(fd, regions[1].off, regionSize)
	if err != nil {
		unmapRange(map0)
		unmapRange(headerMap)
		return nil, err
	}

	j := &Journal{
		file:   file,
		header: headerMap,
	}
	h := j.header
	binary.LittleEndian.PutUint32(h[8:], formatVersion)
	binary.LittleEndian.PutUint64(h[16:], regionSize)
	putID(h[buildIDOff:], opts.BuildID)
	putID(h[imageIDOff:], opts.ImageID)
	binary.LittleEndian.PutUint32(h[headerCRCOff:], headerCRC(h, headerMagic))
	for i, r := range regions {
		j.storeRegion(i, r)
	}

	// The first generation is 1, so region 1 is active first.
	const gen = 1
	writeRegionHeader(map1, gen, 1 /* startSeq */)
	active := uint64(gen)
	if incomplete {
		active |= incompleteBit
	}
	j.storeActive(active)
	// Write the magic last: until it is written, Open treats the journal as
	// incomplete.
	atomicStore64(h[0:8], binary.LittleEndian.Uint64(headerMagic[:]))

	j.mu.Lock()
	j.regionMaps = [2][]byte{map0, map1}
	j.mu.Unlock()
	return j, nil
}

func mmapRange(fd int, off, size uint64) ([]byte, error) {
	m, err := unix.Mmap(fd, int64(off), int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap journal range [%#x, +%#x): %w", off, size, err)
	}
	return m, nil
}

func unmapRange(m []byte) {
	if m != nil {
		if err := unix.Munmap(m); err != nil {
			log.Warningf("Failed to unmap journal range: %v", err)
		}
	}
}

func putID(b []byte, id string) {
	binary.LittleEndian.PutUint16(b, uint16(len(id)))
	copy(b[2:2+maxIDLen], id)
}

func getID(b []byte) (string, error) {
	n := int(binary.LittleEndian.Uint16(b))
	if n > maxIDLen {
		return "", fmt.Errorf("ID length %d exceeds %d", n, maxIDLen)
	}
	return string(b[2 : 2+n]), nil
}

// headerCRC returns the checksum of the immutable fields of header h, with
// the given magic.
func headerCRC(h []byte, magic [8]byte) uint32 {
	tab := castagnoli()
	c := crc32.Update(0, tab, magic[:])
	c = crc32.Update(c, tab, h[8:activeOff])
	return crc32.Update(c, tab, h[buildIDOff:regionDescOff])
}

// checkHeader validates header h against opts and returns the region size.
func checkHeader(h []byte, opts Options) (uint64, error) {
	regionSize, err := checkHeaderFormat(h)
	if err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint64(h[activeOff:])&incompleteBit != 0 {
		return 0, ErrIncomplete
	}
	buildID, err := getID(h[buildIDOff:])
	if err != nil {
		return 0, err
	}
	if buildID != opts.BuildID {
		return 0, fmt.Errorf("journal was written by build %q, but this is build %q", buildID, opts.BuildID)
	}
	imageID, err := getID(h[imageIDOff:])
	if err != nil {
		return 0, err
	}
	if opts.ImageID != "" && imageID != opts.ImageID {
		return 0, &ImageMismatchError{Journal: imageID, Want: opts.ImageID}
	}
	return regionSize, nil
}

// checkHeaderFormat validates the magic, checksum, format version and region
// size of header h, and returns the region size.
func checkHeaderFormat(h []byte) (uint64, error) {
	var magic [8]byte
	copy(magic[:], h)
	if magic != headerMagic {
		return 0, fmt.Errorf("journal has bad magic %q", magic[:])
	}
	if got, want := binary.LittleEndian.Uint32(h[headerCRCOff:]), headerCRC(h, headerMagic); got != want {
		return 0, fmt.Errorf("journal header checksum is %#x, want %#x", got, want)
	}
	if v := binary.LittleEndian.Uint32(h[8:]); v != formatVersion {
		return 0, fmt.Errorf("journal format version is %d, want %d", v, formatVersion)
	}
	regionSize := binary.LittleEndian.Uint64(h[16:])
	if regionSize < minRegionSize || regionSize > maxRegionSize || !hostarch.IsPageAligned(regionSize) {
		return 0, fmt.Errorf("journal has invalid region size %d", regionSize)
	}
	return regionSize, nil
}

// ErrIncomplete is returned by Open if the journal is incomplete or was never
// initialized. See CreateIncomplete.
var ErrIncomplete = errors.New("journal is incomplete")

// ImageMismatchError is returned by Open when the journal was created for a
// different image.
type ImageMismatchError struct {
	Journal string
	Want    string
}

// Error implements error.Error.
func (e *ImageMismatchError) Error() string {
	return fmt.Sprintf("journal was created for image %q, but the image is %q", e.Journal, e.Want)
}

func (j *Journal) storeActive(v uint64) {
	atomicStore64(j.header[activeOff:activeOff+8], v)
}

func loadRegionFromHeader(hdr []byte, i int) region {
	off := regionDescOff + 16*i
	return region{
		off:  binary.LittleEndian.Uint64(hdr[off:]),
		size: binary.LittleEndian.Uint64(hdr[off+8:]),
	}
}

// storeRegion writes the descriptor of region slot i to the header. The
// region must not be active.
func (j *Journal) storeRegion(i int, r region) {
	off := regionDescOff + 16*i
	atomicStore64(j.header[off:off+8], r.off)
	atomicStore64(j.header[off+8:off+16], r.size)
}

func writeRegionHeader(regionMap []byte, gen, startSeq uint64) {
	h := regionMap[:regionHeaderSize]
	clear(h)
	binary.LittleEndian.PutUint32(h[0:], regionMagic)
	binary.LittleEndian.PutUint64(h[8:], gen)
	binary.LittleEndian.PutUint64(h[16:], startSeq)
	binary.LittleEndian.PutUint32(h[24:], crc32.Checksum(h[:24], castagnoli()))
}

// checkRegionHeader validates the header of regionMap and returns the sequence
// number of its first record.
func checkRegionHeader(regionMap []byte, gen uint64) (uint64, error) {
	h := regionMap[:regionHeaderSize]
	if m := binary.LittleEndian.Uint32(h[0:]); m != regionMagic {
		return 0, fmt.Errorf("active journal region has bad magic %#x", m)
	}
	if got, want := binary.LittleEndian.Uint32(h[24:]), crc32.Checksum(h[:24], castagnoli()); got != want {
		return 0, fmt.Errorf("active journal region header checksum is %#x, want %#x", got, want)
	}
	if g := binary.LittleEndian.Uint64(h[8:]); g != gen {
		return 0, fmt.Errorf("active journal region has generation %d, want %d", g, gen)
	}
	return binary.LittleEndian.Uint64(h[16:]), nil
}

// Close stops appends, unmaps the journal's mappings, and closes the journal
// file. Records appended after Close are dropped. Close does not modify the
// journal file, so that a new sandbox can replay the journal.
func (j *Journal) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	j.closed = true
	for i := range j.regionMaps {
		unmapRange(j.regionMaps[i])
		j.regionMaps[i] = nil
	}
	unmapRange(j.header)
	j.header = nil
	if err := j.file.Close(); err != nil {
		log.Warningf("tmpfs journal: failed to close journal file: %v", err)
	}
}

func direntAddLen(name string) uint64 {
	return 8 + 8 + 2 + uint64(len(name))
}

// SnapshotSizer computes the size of snapshot records for BeginSnapshot. It
// has the same record methods as Snapshot.
type SnapshotSizer struct {
	size uint64
}

// Size returns the total size of the records.
func (z *SnapshotSizer) Size() uint64 {
	return z.size
}

// Inode adds the size of the records that Snapshot.Inode writes.
func (z *SnapshotSizer) Inode(r *InodeRecord) {
	z.size += recordSize(r.payloadLen())
	if r.Mode&modeTypeMask == modeRegular {
		z.size += recordSize(24)
	}
}

// DirentAdd adds the size of a RecordDirentAdd record.
func (z *SnapshotSizer) DirentAdd(parent uint64, name string, child uint64) {
	z.size += recordSize(direntAddLen(name))
}

// ExtentSet adds the size of a RecordExtentSet record.
func (z *SnapshotSizer) ExtentSet(ino, off, length, mfOff uint64) {
	z.size += recordSize(32)
}
