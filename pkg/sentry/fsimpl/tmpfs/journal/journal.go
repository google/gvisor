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
// is stored in a disk-backed filestore. The journal lets a new sentry rebuild
// the tmpfs after the previous sentry crashed or stopped, without copying
// file data.
//
// The journal file has a 4 KiB header and two regions. The header holds the
// offset and size of each region, so that a region can move and grow when a
// snapshot does not fit. One region is active at a time. It holds a snapshot
// of the full tmpfs state, followed by records for later changes. The writer
// appends records through a shared mapping of the file, so an append is a
// memory copy with no system calls. A sentry crash cannot lose appended
// records, since the host page cache keeps them. Host crashes are out of
// scope; the journal never calls fsync.
//
// Compaction writes a new snapshot to the inactive region, then makes it
// active with one atomic store to the header. Until that store, the old
// region stays valid, so a crash during compaction is safe. Before it writes
// the snapshot, compaction moves the inactive region to a larger free range
// of the file if the snapshot may not fit. The inactive region is empty at
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
	"math"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
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
// filestoreEnd is a high-water mark: it is at least the end of every extent
// in an EXTENT_SET record in the active region. Open refuses extents beyond
// it. The host can shrink the filestore to it before the sandbox starts; see
// FilestoreEnd.
const (
	headerSize      = 4096
	formatVersion   = 3
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

	// incompleteBit is set in a new journal for a filestore that an image
	// (for example a checkpoint) populates. The first Commit of a Journal
	// returned by Reinit clears it.
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

	// maxFileSize bounds the size of the journal file. Regions are placed
	// at the start of the file or after the active region, which keeps
	// the file below this size.
	maxFileSize = headerSize + 4*maxRegionSize

	// snapshotSlack is added to the space for a snapshot.
	snapshotSlack = hostarch.PageSize
)

// Options configures Open.
type Options struct {
	// BuildID identifies the binary that writes the journal. Open refuses a
	// journal written by a different binary.
	BuildID string

	// ImageID identifies the lower layer of the overlay. Open refuses a
	// journal created for a different image.
	ImageID string

	// RegionSize is the minimum size of each region. It is only used when
	// a new journal is created. If it is 0, DefaultRegionSize is used.
	RegionSize uint64

	// FilestoreSize is the current size of the filestore. Replayed extents
	// must be within it.
	FilestoreSize uint64
}

// Journal is an open journal.
type Journal struct {
	// file is the journal file. file is immutable.
	file *os.File

	// mapping is a shared mapping of the whole file. After Open or create
	// returns, mapping is protected by mu.
	mapping []byte

	// regionSize is the minimum size of a region. regionSize is immutable.
	regionSize uint64

	// needCompaction is called, without mu held, when the active region is
	// half full or full. needCompaction is immutable after
	// SetCompactionRequester.
	needCompaction func()

	mu sync.Mutex

	// gen is the generation of the active region.
	//
	// +checklocks:mu
	gen uint64

	// broken is true if a record was dropped because the active region was
	// full.
	//
	// +checklocks:mu
	broken bool

	// active is the writer for the active region.
	//
	// +checklocks:mu
	active regionWriter

	// next is the writer for the inactive region during compaction, and nil
	// otherwise.
	//
	// +checklocks:mu
	next *regionWriter

	// filestoreEnd is the value of the filestoreEnd header field.
	//
	// +checklocks:mu
	filestoreEnd uint64

	// nextEnd is the maximum extent end in EXTENT_SET records in the
	// inactive region during compaction.
	//
	// +checklocks:mu
	nextEnd uint64

	// regions holds the region descriptors, as in the header.
	//
	// +checklocks:mu
	regions [2]region

	// fileSize is the size of mapping.
	//
	// +checklocks:mu
	fileSize uint64

	// requested is true if needCompaction was called and compaction has
	// not finished since.
	//
	// +checklocks:mu
	requested bool

	// closed is true after Close. Appends are dropped after Close.
	//
	// +checklocks:mu
	closed bool
}

// region describes a region of the journal file.
type region struct {
	off  uint64
	size uint64
}

func (r region) end() uint64 {
	return r.off + r.size
}

func (r region) overlaps(o region) bool {
	return r.off < o.end() && o.off < r.end()
}

// valid returns true if r is a well-formed region in a file of size
// fileSize.
func (r region) valid(fileSize uint64) bool {
	return r.off >= headerSize && hostarch.IsPageAligned(r.off) &&
		r.size >= minRegionSize && r.size <= maxRegionSize && hostarch.IsPageAligned(r.size) &&
		r.off <= fileSize && r.size <= fileSize-r.off
}

// regionWriter appends records to one region.
type regionWriter struct {
	// base is the offset of the region in the mapping.
	base uint64
	// size is the size of the region.
	size uint64
	// tail is the offset of the next record, relative to base.
	tail uint64
	// nextSeq is the sequence number of the next record.
	nextSeq uint64
	// full is true if an append did not fit.
	full bool
	// reserved is true between reserve and seal.
	reserved bool
}

// Open opens the journal in file and returns it, together with the state
// that it holds. If file is empty, or if its header was never completely
// written, Open initializes a new journal and returns a State with Root == 0.
// Open refuses to use a journal with a different format version, build ID or
// image ID, one that is marked as incomplete (ErrIncomplete) or broken, or one
// whose contents are not valid. In that case, the caller must not start; Open
// never discards an existing journal.
//
// On success, the Journal owns file.
func Open(file *os.File, opts Options) (*Journal, *State, error) {
	if len(opts.BuildID) > maxIDLen || len(opts.ImageID) > maxIDLen {
		return nil, nil, fmt.Errorf("build ID or image ID longer than %d bytes", maxIDLen)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, nil, fmt.Errorf("failed to stat journal: %w", err)
	}
	fresh := stat.Size == 0
	var hdr [headerSize]byte
	if !fresh {
		if stat.Size < headerSize {
			return nil, nil, fmt.Errorf("journal size %d is smaller than its header", stat.Size)
		}
		if _, err := unix.Pread(int(file.Fd()), hdr[:], 0); err != nil {
			return nil, nil, fmt.Errorf("failed to read journal header: %w", err)
		}
		// Initialization writes the magic last. A header without a magic
		// was never completely written.
		fresh = bytes.Equal(hdr[:len(headerMagic)], make([]byte, len(headerMagic)))
	}
	if fresh {
		j, err := create(file, opts, uint64(stat.Size), false /* incomplete */)
		if err != nil {
			return nil, nil, err
		}
		return j, newState(), nil
	}

	regionSize, err := checkHeader(hdr[:], opts)
	if err != nil {
		return nil, nil, err
	}
	if stat.Size > maxFileSize {
		return nil, nil, fmt.Errorf("journal size %d exceeds %d", stat.Size, int64(maxFileSize))
	}
	fileSize := uint64(stat.Size)
	j := &Journal{
		file:       file,
		regionSize: regionSize,
	}
	if err := j.mmap(fileSize); err != nil {
		return nil, nil, err
	}
	active := j.loadActive()
	if active&incompleteBit != 0 {
		j.unmap()
		return nil, nil, ErrIncomplete
	}
	if active&brokenBit != 0 {
		j.unmap()
		return nil, nil, fmt.Errorf("journal overflowed before the previous sandbox stopped; its state is incomplete")
	}
	gen := active
	regions := [2]region{j.loadRegion(0), j.loadRegion(1)}
	r := regions[gen&1]
	if !r.valid(fileSize) {
		j.unmap()
		return nil, nil, fmt.Errorf("active journal region [%#x, +%#x) is not valid in a %#x-byte file", r.off, r.size, fileSize)
	}
	base := r.off
	startSeq, err := j.checkRegionHeader(base, gen)
	if err != nil {
		j.unmap()
		return nil, nil, err
	}
	// Extents must be within both the filestore and the high-water mark. If
	// the mark is too low, for example because a compromised sandbox wrote
	// it, replay fails instead of losing data silently.
	filestoreEnd := j.loadFilestoreEnd()
	limit := min(opts.FilestoreSize, filestoreEnd)
	st, tail, nextSeq, err := replayRegion(j.mapping[base:r.end()], startSeq, limit)
	if err != nil {
		j.unmap()
		if filestoreEnd < opts.FilestoreSize {
			return nil, nil, fmt.Errorf("failed to replay journal with filestore end mark %#x: %w", filestoreEnd, err)
		}
		return nil, nil, fmt.Errorf("failed to replay journal: %w", err)
	}
	j.mu.Lock()
	j.gen = gen
	j.active = regionWriter{base: base, size: r.size, tail: tail, nextSeq: nextSeq}
	j.filestoreEnd = filestoreEnd
	j.regions = regions
	j.fileSize = fileSize
	j.mu.Unlock()
	return j, st, nil
}

// create initializes a new journal in file, whose current size is size.
func create(file *os.File, opts Options, size uint64, incomplete bool) (*Journal, error) {
	regionSize := opts.RegionSize
	if regionSize == 0 {
		regionSize = DefaultRegionSize
	}
	if regionSize < minRegionSize || regionSize > maxRegionSize || !hostarch.IsPageAligned(regionSize) {
		return nil, fmt.Errorf("invalid region size %d", regionSize)
	}
	total := headerSize + 2*regionSize
	if size != 0 {
		// Discard the old contents of the file.
		if err := file.Truncate(0); err != nil {
			return nil, fmt.Errorf("failed to truncate journal: %w", err)
		}
	}
	if err := file.Truncate(int64(total)); err != nil {
		return nil, fmt.Errorf("failed to size journal: %w", err)
	}
	j := &Journal{
		file:       file,
		regionSize: regionSize,
	}
	if err := j.mmap(total); err != nil {
		return nil, err
	}
	h := j.mapping[:headerSize]
	clear(h)
	binary.LittleEndian.PutUint32(h[8:], formatVersion)
	binary.LittleEndian.PutUint64(h[16:], regionSize)
	putID(h[buildIDOff:], opts.BuildID)
	putID(h[imageIDOff:], opts.ImageID)
	binary.LittleEndian.PutUint32(h[headerCRCOff:], headerCRC(h, headerMagic))
	regions := [2]region{
		{off: headerSize, size: regionSize},
		{off: headerSize + regionSize, size: regionSize},
	}
	for i, r := range regions {
		j.storeRegion(i, r)
	}

	// The first generation is 1, so region 1 is active first.
	const gen = 1
	base := regions[gen].off
	j.writeRegionHeader(base, gen, 1 /* startSeq */)
	active := uint64(gen)
	if incomplete {
		active |= incompleteBit
	}
	j.storeActive(active)
	// Write the magic last: until it is written, Open treats the journal as
	// new.
	atomicStore64(h[0:8], binary.LittleEndian.Uint64(headerMagic[:]))

	j.mu.Lock()
	j.gen = gen
	j.active = regionWriter{base: base, size: regionSize, tail: regionHeaderSize, nextSeq: 1}
	j.regions = regions
	j.fileSize = total
	j.mu.Unlock()
	return j, nil
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
	// The host, whose binary and build ID can differ from the sandbox's,
	// writes the header of an incomplete journal, so check the mark first.
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
	if imageID != opts.ImageID {
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

// FilestoreEnd returns the filestoreEnd header field of the journal in file.
// No extent that Open accepts ends beyond it, so the filestore can be shrunk
// to it before the journal is opened. ok is false if file does not hold a
// valid journal header, or if the journal is marked as broken or incomplete;
// the caller must then not use end. FilestoreEnd does not check the build and
// image IDs, since the mark does not depend on them. FilestoreEnd does not
// take ownership of file.
func FilestoreEnd(file *os.File) (end uint64, ok bool, err error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return 0, false, fmt.Errorf("failed to stat journal: %w", err)
	}
	if stat.Size < headerSize {
		return 0, false, nil
	}
	var hdr [headerSize]byte
	if _, err := unix.Pread(int(file.Fd()), hdr[:], 0); err != nil {
		return 0, false, fmt.Errorf("failed to read journal header: %w", err)
	}
	if _, err := checkHeaderFormat(hdr[:]); err != nil {
		return 0, false, nil
	}
	if binary.LittleEndian.Uint64(hdr[activeOff:])&activeFlags != 0 {
		return 0, false, nil
	}
	return binary.LittleEndian.Uint64(hdr[filestoreEndOff:]), true, nil
}

// Describe returns the image ID and the active generation of the journal in
// file, for messages. It does not check the build ID or the image ID.
// Describe does not take ownership of file.
func Describe(file *os.File) (imageID string, generation uint64, err error) {
	var hdr [headerSize]byte
	if _, err := unix.Pread(int(file.Fd()), hdr[:], 0); err != nil {
		return "", 0, fmt.Errorf("failed to read journal header: %w", err)
	}
	if bytes.Equal(hdr[:len(headerMagic)], make([]byte, len(headerMagic))) {
		return "", 0, fmt.Errorf("journal header was never completely written")
	}
	if _, err := checkHeaderFormat(hdr[:]); err != nil {
		return "", 0, err
	}
	imageID, err = getID(hdr[imageIDOff:])
	if err != nil {
		return "", 0, err
	}
	return imageID, binary.LittleEndian.Uint64(hdr[activeOff:]) &^ activeFlags, nil
}

// ErrIncomplete is returned by Open if the journal is incomplete. See
// CreateIncomplete.
var ErrIncomplete = errors.New("journal is incomplete")

// CreateIncomplete initializes a new journal in file and marks it as
// incomplete. Call it before an image populates a new filestore. Until a
// Journal returned by Reinit commits its first snapshot, Open refuses the
// journal with ErrIncomplete. CreateIncomplete does not take ownership of
// file.
func CreateIncomplete(file *os.File, opts Options) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fmt.Errorf("failed to stat journal: %w", err)
	}
	j, err := create(file, opts, uint64(stat.Size), true /* incomplete */)
	if err != nil {
		return err
	}
	j.unmap()
	return nil
}

// Incomplete returns true if the journal in file is marked as incomplete.
func Incomplete(file *os.File) (bool, error) {
	var buf [8]byte
	if _, err := unix.Pread(int(file.Fd()), buf[:], activeOff); err != nil {
		return false, fmt.Errorf("failed to read journal header: %w", err)
	}
	return binary.LittleEndian.Uint64(buf[:])&incompleteBit != 0, nil
}

// Reinit discards the contents of the journal in file and returns a new,
// empty Journal that is marked as incomplete. Its first committed snapshot
// clears the mark. On success, the Journal owns file.
func Reinit(file *os.File, opts Options) (*Journal, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, fmt.Errorf("failed to stat journal: %w", err)
	}
	return create(file, opts, uint64(stat.Size), true /* incomplete */)
}

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

func (j *Journal) mmap(size uint64) error {
	m, err := unix.Mmap(int(j.file.Fd()), 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("failed to mmap journal: %w", err)
	}
	j.mapping = m
	return nil
}

func (j *Journal) unmap() {
	if j.mapping != nil {
		if err := unix.Munmap(j.mapping); err != nil {
			log.Warningf("Failed to unmap journal: %v", err)
		}
		j.mapping = nil
	}
}

func (j *Journal) loadActive() uint64 {
	return atomicLoad64(j.mapping[activeOff : activeOff+8])
}

func (j *Journal) storeActive(v uint64) {
	atomicStore64(j.mapping[activeOff:activeOff+8], v)
}

func (j *Journal) loadFilestoreEnd() uint64 {
	return atomicLoad64(j.mapping[filestoreEndOff : filestoreEndOff+8])
}

// raiseFilestoreEndLocked raises the filestoreEnd header field to cover an
// extent that ends at end. The caller must call it before it seals the
// record of the extent.
//
// +checklocks:j.mu
func (j *Journal) raiseFilestoreEndLocked(end uint64) {
	if end > j.filestoreEnd {
		j.filestoreEnd = end
		atomicStore64(j.mapping[filestoreEndOff:filestoreEndOff+8], end)
	}
}

// extentEnd returns the end of the filestore range of an extent.
func extentEnd(length, mfOff uint64) uint64 {
	end := mfOff + length
	if end < mfOff {
		return math.MaxUint64
	}
	return end
}

// loadRegion returns the descriptor of region slot i from the header.
func (j *Journal) loadRegion(i int) region {
	off := regionDescOff + 16*i
	return region{
		off:  atomicLoad64(j.mapping[off : off+8]),
		size: atomicLoad64(j.mapping[off+8 : off+16]),
	}
}

// storeRegion writes the descriptor of region slot i to the header. The
// region must not be active.
func (j *Journal) storeRegion(i int, r region) {
	off := regionDescOff + 16*i
	atomicStore64(j.mapping[off:off+8], r.off)
	atomicStore64(j.mapping[off+8:off+16], r.size)
}

// remapLocked replaces the mapping with a mapping of the first size bytes of
// the file. On failure, the old mapping stays.
//
// +checklocks:j.mu
func (j *Journal) remapLocked(size uint64) error {
	m, err := unix.Mmap(int(j.file.Fd()), 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("failed to mmap journal: %w", err)
	}
	old := j.mapping
	j.mapping = m
	j.fileSize = size
	if err := unix.Munmap(old); err != nil {
		log.Warningf("Failed to unmap journal: %v", err)
	}
	return nil
}

// prepareRegionLocked makes the region in slot, which must be inactive,
// large enough for need bytes. If the region is too small, too large, or not
// valid, prepareRegionLocked moves it to a free range of the file: before
// the active region if it fits there, or else after the active region. It
// then resizes the file to end with the last region, and punches a hole over
// the old range.
//
// +checklocks:j.mu
func (j *Journal) prepareRegionLocked(slot int, need uint64) error {
	if need > maxRegionSize {
		return fmt.Errorf("journal snapshot needs %d bytes, more than the maximum region size %d", need, uint64(maxRegionSize))
	}
	cur := j.regions[slot]
	active := j.regions[1-slot]
	// Leave room for appends after the snapshot, so that the next
	// compaction, which starts when the region is half full, is not due at
	// once.
	want := max(j.regionSize, hostarch.MustPageRoundUp(min(2*need, maxRegionSize)))
	if cur.valid(j.fileSize) && !cur.overlaps(active) && cur.size >= need && cur.size <= max(j.regionSize, 2*want) {
		return nil
	}
	next := region{off: headerSize, size: want}
	if next.overlaps(active) {
		next.off = active.end()
	}
	fileSize := max(active.end(), next.end())
	if fileSize > maxFileSize {
		return fmt.Errorf("journal file would grow to %d bytes, more than %d", fileSize, uint64(maxFileSize))
	}
	if fileSize > j.fileSize {
		if err := j.file.Truncate(int64(fileSize)); err != nil {
			return fmt.Errorf("failed to grow journal to %d bytes: %w", fileSize, err)
		}
		if err := j.remapLocked(fileSize); err != nil {
			return err
		}
	}
	j.storeRegion(slot, next)
	j.regions[slot] = next
	if cur.valid(j.fileSize) && !cur.overlaps(active) {
		// Free the disk space of the old region. Its contents are no longer
		// needed, and a hole reads as zeros.
		if err := unix.Fallocate(int(j.file.Fd()), unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, int64(cur.off), int64(cur.size)); err != nil {
			log.Debugf("tmpfs journal: failed to punch hole in old region: %v", err)
		}
	}
	if fileSize < j.fileSize {
		// Shrink the file. This is optional, so ignore failures.
		if err := j.remapLocked(fileSize); err != nil {
			log.Warningf("tmpfs journal: failed to shrink mapping: %v", err)
		} else if err := j.file.Truncate(int64(fileSize)); err != nil {
			log.Warningf("tmpfs journal: failed to shrink journal: %v", err)
		}
	}
	log.Infof("tmpfs journal: moved region %d to [%#x, +%#x) for a %d-byte snapshot; journal size is %d bytes", slot, next.off, next.size, need, j.fileSize)
	return nil
}

func (j *Journal) writeRegionHeader(base, gen, startSeq uint64) {
	h := j.mapping[base : base+regionHeaderSize]
	clear(h)
	binary.LittleEndian.PutUint32(h[0:], regionMagic)
	binary.LittleEndian.PutUint64(h[8:], gen)
	binary.LittleEndian.PutUint64(h[16:], startSeq)
	binary.LittleEndian.PutUint32(h[24:], crc32.Checksum(h[:24], castagnoli()))
}

// checkRegionHeader validates the header of the region at base and returns
// the sequence number of its first record.
func (j *Journal) checkRegionHeader(base, gen uint64) (uint64, error) {
	h := j.mapping[base : base+regionHeaderSize]
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

// SetCompactionRequester sets the function that the Journal calls when the
// active region is half full. fn is called without any Journal lock held, and
// must not block. The Journal calls fn at most once until the next call to
// Compact.
//
// Preconditions: No other goroutine is using j.
func (j *Journal) SetCompactionRequester(fn func()) {
	j.needCompaction = fn
}

// Close stops appends and releases the journal's resources. Records appended
// after Close are dropped. Close does not modify the journal file, so that a
// new sandbox can replay it.
func (j *Journal) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	j.closed = true
	j.next = nil
	j.unmap()
	j.file.Close()
}

// CompactionPending returns true if the Journal requested a compaction that
// has not finished yet.
func (j *Journal) CompactionPending() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.requested
}

// Broken returns true if a record was dropped because the active region was
// full, and no compaction has finished since.
func (j *Journal) Broken() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.broken
}

// reserve returns the payload buffer for a record of the given payload length
// at the tail of w, or nil if the record does not fit.
//
// +checklocks:j.mu
func (j *Journal) reserve(w *regionWriter, payloadLen uint64) []byte {
	if w.full {
		return nil
	}
	size := recordSize(payloadLen)
	if size > w.size-w.tail {
		w.full = true
		return nil
	}
	w.reserved = true
	off := w.base + w.tail + recordHeaderSize
	return j.mapping[off : off+payloadLen]
}

// seal completes the record reserved at the tail of w. The payload must
// already be written. seal writes the header fields and the checksum, then
// the magic, last, with an atomic store. A crash before the magic is written
// leaves a record that replay rejects.
//
// +checklocks:j.mu
func (j *Journal) seal(w *regionWriter, typ RecordType, payloadLen uint64) {
	size := recordSize(payloadLen)
	off := w.base + w.tail
	rec := j.mapping[off : off+size]
	binary.LittleEndian.PutUint32(rec[4:], uint32(payloadLen))
	binary.LittleEndian.PutUint64(rec[8:], w.nextSeq)
	binary.LittleEndian.PutUint16(rec[16:], uint16(typ))
	binary.LittleEndian.PutUint16(rec[18:], 0)
	binary.LittleEndian.PutUint32(rec[20:], 0)
	crc := crc32.Checksum(rec[4:recordHeaderSize+payloadLen], castagnoli())
	binary.LittleEndian.PutUint32(rec[recordHeaderSize+payloadLen:], crc)
	atomicStore32(rec[0:4], recordMagic)
	w.tail += size
	w.nextSeq++
	w.reserved = false
}

// beginLocked returns the buffer into which the caller must encode the
// payload of a record of the given length, or nil if the record is dropped.
// The caller must then call endLocked.
//
// +checklocks:j.mu
func (j *Journal) beginLocked(payloadLen uint64) []byte {
	if j.closed {
		return nil
	}
	if buf := j.reserve(&j.active, payloadLen); buf != nil {
		return buf
	}
	if !j.broken {
		// The record is lost from the active region. Mark the journal
		// broken, so that a crash before the next compaction refuses to
		// replay an incomplete state.
		log.Warningf("tmpfs journal: active region is full; the journal is unusable until compaction finishes")
		j.broken = true
		j.storeActive(j.loadActive() | brokenBit)
	}
	if j.next != nil {
		return j.reserve(j.next, payloadLen)
	}
	return nil
}

// endLocked seals the record started by beginLocked. During compaction, it
// also copies the record to the inactive region. It returns true if the
// caller must call j.needCompaction after it unlocks j.mu.
//
// +checklocks:j.mu
func (j *Journal) endLocked(typ RecordType, payloadLen uint64) bool {
	if j.closed {
		return false
	}
	if j.active.reserved {
		if j.next != nil {
			src := j.active.base + j.active.tail + recordHeaderSize
			if dst := j.reserve(j.next, payloadLen); dst != nil {
				copy(dst, j.mapping[src:src+payloadLen])
			}
		}
		j.seal(&j.active, typ, payloadLen)
	}
	if j.next != nil && j.next.reserved {
		j.seal(j.next, typ, payloadLen)
	}
	if j.requested || j.needCompaction == nil {
		return false
	}
	if j.active.full || j.active.tail > j.active.size/2 {
		j.requested = true
		return true
	}
	return false
}

// +checklocksrelease:j.mu
func (j *Journal) end(typ RecordType, payloadLen uint64) {
	request := j.endLocked(typ, payloadLen)
	j.mu.Unlock()
	if request {
		j.needCompaction()
	}
}

// Inode appends a RecordInode record.
func (j *Journal) Inode(r *InodeRecord) {
	n := r.payloadLen()
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		e := encoder{buf: buf}
		r.encode(&e)
	}
	j.end(RecordInode, n)
}

// InodeFree appends a RecordInodeFree record.
func (j *Journal) InodeFree(ino uint64) {
	const n = 8
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		binary.LittleEndian.PutUint64(buf, ino)
	}
	j.end(RecordInodeFree, n)
}

// DirentAdd appends a RecordDirentAdd record.
func (j *Journal) DirentAdd(parent uint64, name string, child uint64) {
	n := direntAddLen(name)
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		encodeDirentAdd(buf, parent, name, child)
	}
	j.end(RecordDirentAdd, n)
}

func direntAddLen(name string) uint64 {
	return 8 + 8 + 2 + uint64(len(name))
}

func encodeDirentAdd(buf []byte, parent uint64, name string, child uint64) {
	e := encoder{buf: buf}
	e.u64(parent)
	e.u64(child)
	e.str16(name)
}

// DirentDel appends a RecordDirentDel record.
func (j *Journal) DirentDel(parent uint64, name string) {
	n := 8 + 2 + uint64(len(name))
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		e := encoder{buf: buf}
		e.u64(parent)
		e.str16(name)
	}
	j.end(RecordDirentDel, n)
}

const renameExchange = 1

// Rename appends a RecordRename record. If exchange is false, the entry
// oldName in oldParent moves to newName in newParent, and replaces any entry
// with that name. If exchange is true, the two entries are exchanged.
func (j *Journal) Rename(oldParent uint64, oldName string, newParent uint64, newName string, exchange bool) {
	var flags uint32
	if exchange {
		flags = renameExchange
	}
	n := 8 + 8 + 4 + 2 + uint64(len(oldName)) + 2 + uint64(len(newName))
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		e := encoder{buf: buf}
		e.u64(oldParent)
		e.u64(newParent)
		e.u32(flags)
		e.str16(oldName)
		e.str16(newName)
	}
	j.end(RecordRename, n)
}

func encodeExtent(buf []byte, ino, off, length, mfOff uint64) {
	binary.LittleEndian.PutUint64(buf[0:], ino)
	binary.LittleEndian.PutUint64(buf[8:], off)
	binary.LittleEndian.PutUint64(buf[16:], length)
	if len(buf) > 24 {
		binary.LittleEndian.PutUint64(buf[24:], mfOff)
	}
}

// ExtentSet appends a RecordExtentSet record.
func (j *Journal) ExtentSet(ino, off, length, mfOff uint64) {
	const n = 32
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		encodeExtent(buf, ino, off, length, mfOff)
		// The record may go to both regions. Cover it in the mark before
		// it is sealed, and in nextEnd for the inactive region.
		end := extentEnd(length, mfOff)
		j.raiseFilestoreEndLocked(end)
		if j.next != nil {
			j.nextEnd = max(j.nextEnd, end)
		}
	}
	j.end(RecordExtentSet, n)
}

// ExtentClear appends a RecordExtentClear record.
func (j *Journal) ExtentClear(ino, off, length uint64) {
	const n = 24
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		encodeExtent(buf, ino, off, length, 0)
	}
	j.end(RecordExtentClear, n)
}

// Snapshot writes a new snapshot to the inactive region. Records that are
// appended to the Journal while a Snapshot is in progress are also written
// to the inactive region, in order with the snapshot records.
//
// For each inode, the snapshot records must reflect a state at least as new
// as every record for that inode that was appended before them. Callers
// ensure this by holding the locks that serialize changes to each inode while
// they write its snapshot records.
type Snapshot struct {
	j *Journal
}

// BeginSnapshot starts a compaction, and writes a RecordRoot record with the
// given root inode number and next free inode number as the first snapshot
// record. size is the expected total size of the other snapshot records; see
// SnapshotSizer. If the inactive region may be too small for them, together
// with the records that are appended during the compaction, BeginSnapshot
// first moves it to a larger range of the file. The caller must call Commit
// or Abort on the returned Snapshot.
func (j *Journal) BeginSnapshot(rootIno, nextIno, size uint64) (*Snapshot, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil, fmt.Errorf("journal is closed")
	}
	if j.next != nil {
		return nil, fmt.Errorf("compaction already in progress")
	}
	gen := j.gen + 1
	slot := int(gen & 1)
	need := regionHeaderSize + recordSize(16) + snapshotSlack
	if size > (maxRegionSize-need)/2 {
		need = maxRegionSize + 1
	} else {
		need += 2 * size
	}
	// The inactive region is not replayed, so it can move. Its new
	// descriptor is in the header before Commit makes it active.
	if err := j.prepareRegionLocked(slot, need); err != nil {
		return nil, err
	}
	r := j.regions[slot]
	base := r.off
	// Sequence numbers increase across regions, so that stale records left
	// in the new region by its previous use always have lower sequence
	// numbers than the new region's first record.
	startSeq := j.active.nextSeq
	j.writeRegionHeader(base, gen, startSeq)
	j.next = &regionWriter{base: base, size: r.size, tail: regionHeaderSize, nextSeq: startSeq}
	j.nextEnd = 0
	const n = 16
	if buf := j.reserve(j.next, n); buf != nil {
		binary.LittleEndian.PutUint64(buf[0:], rootIno)
		binary.LittleEndian.PutUint64(buf[8:], nextIno)
		j.seal(j.next, RecordRoot, n)
	}
	return &Snapshot{j: j}, nil
}

// snapshotBegin returns the buffer for the payload of a snapshot record, or
// nil if the record is dropped. The caller must call j.snapshotEnd.
//
// +checklocksacquire:j.mu
func (j *Journal) snapshotBegin(payloadLen uint64) []byte {
	j.mu.Lock()
	if j.next == nil {
		return nil
	}
	return j.reserve(j.next, payloadLen)
}

// +checklocksrelease:j.mu
func (j *Journal) snapshotEnd(typ RecordType, payloadLen uint64) {
	if j.next != nil && j.next.reserved {
		j.seal(j.next, typ, payloadLen)
	}
	j.mu.Unlock()
}

// Inode writes a RecordInode record. For a regular file, it also writes a
// RecordExtentClear record for the whole file, so that the snapshot replaces
// the extents set by earlier records.
func (s *Snapshot) Inode(r *InodeRecord) {
	n := r.payloadLen()
	if buf := s.j.snapshotBegin(n); buf != nil {
		e := encoder{buf: buf}
		r.encode(&e)
	}
	s.j.snapshotEnd(RecordInode, n)
	if r.Mode&modeTypeMask == modeRegular {
		const n = 24
		if buf := s.j.snapshotBegin(n); buf != nil {
			encodeExtent(buf, r.Ino, 0, maxFileOffset, 0)
		}
		s.j.snapshotEnd(RecordExtentClear, n)
	}
}

// DirentAdd writes a RecordDirentAdd record.
func (s *Snapshot) DirentAdd(parent uint64, name string, child uint64) {
	n := direntAddLen(name)
	if buf := s.j.snapshotBegin(n); buf != nil {
		encodeDirentAdd(buf, parent, name, child)
	}
	s.j.snapshotEnd(RecordDirentAdd, n)
}

// ExtentSet writes a RecordExtentSet record.
func (s *Snapshot) ExtentSet(ino, off, length, mfOff uint64) {
	const n = 32
	if buf := s.j.snapshotBegin(n); buf != nil {
		encodeExtent(buf, ino, off, length, mfOff)
		// Until Commit, the mark must also cover the active region, so
		// it can only grow here.
		end := extentEnd(length, mfOff)
		s.j.raiseFilestoreEndLocked(end)
		s.j.nextEnd = max(s.j.nextEnd, end)
	}
	s.j.snapshotEnd(RecordExtentSet, n)
}

// ErrSnapshotOverflow is returned by Commit if the snapshot and the records
// that were appended during the compaction did not fit in the region. The
// caller can retry with a larger size.
var ErrSnapshotOverflow = errors.New("journal snapshot does not fit in its region")

// Commit makes the snapshot the active region. If the snapshot did not fit in
// the region, Commit returns an error that wraps ErrSnapshotOverflow, and the
// old region stays active.
func (s *Snapshot) Commit() error {
	j := s.j
	j.mu.Lock()
	defer j.mu.Unlock()
	next := j.next
	j.next = nil
	j.requested = false
	if next == nil {
		return fmt.Errorf("journal closed during compaction")
	}
	if next.full {
		return fmt.Errorf("%w: region size is %d bytes", ErrSnapshotOverflow, next.size)
	}
	// This single atomic store makes the new region active and clears
	// brokenBit and incompleteBit.
	j.gen++
	j.storeActive(j.gen)
	j.active = *next
	j.broken = false
	// Before this point, the mark covers both regions. Shrink it to the
	// new active region. A crash between the two stores leaves a mark that is
	// too high, which is safe.
	j.filestoreEnd = j.nextEnd
	atomicStore64(j.mapping[filestoreEndOff:filestoreEndOff+8], j.nextEnd)
	return nil
}

// Abort abandons the snapshot. The old region stays active.
func (s *Snapshot) Abort() {
	j := s.j
	j.mu.Lock()
	defer j.mu.Unlock()
	j.next = nil
	j.requested = false
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
