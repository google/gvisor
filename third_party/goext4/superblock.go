package goext4

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"strings"
	"time"

	"encoding/binary"
)

const (
	// Ext4Magic is defined as EXT4_SUPER_MAGIC in include/uapi/linux/magic.h .
	Ext4Magic = 0xef53

	// SuperblockSize is the size of the ext4 superblock.
	SuperblockSize = 1024

	// Superblock0Offset is the position of the first superblock after the
	// bootloader code.
	Superblock0Offset = int64(1024)
)

// Error thrown when superblock magic number does not match Ext4Magic.
var (
	ErrNotExt4 = errors.New("not ext4")
)

// File system states.
const (
	SbStateCleanlyUnmounted      = 0x0001
	SbStateErrorsDetected        = 0x0002
	SbStateOrphansBeingRecovered = 0x0004
)

// Behaviour when detecting errors.
const (
	SbErrorsContinue        = 1
	SbErrorsRemountReadonly = 2
	SbErrorsPanic           = 3
)

// Codes for operating systems.
const (
	SbOsLinux   = 0
	SbOsHurd    = 1
	SbOsMasix   = 2
	SbOsFreebsd = 3
	SbOsLites   = 4
)

// Revision levels.
const (
	SbRevlevelGoodOldRev = 0 /* The good old (original) format */
	SbRevlevelDynamicRev = 1 /* V2 format w/ dynamic inode sizes */
)

// Legal values for the dx_root hash_version field.
const (
	SbDefHashVersionLegacy          = 0x0
	SbDefHashVersionHalfMd4         = 0x1
	SbDefHashVersionTea             = 0x2
	SbDefHashVersionLegacyUnsigned  = 0x3
	SbDefHashVersionHalfMd4Unsigned = 0x4
	SbDefHashVersionTeaUnsigned     = 0x5
)

// Default mount options.
const (
	SbMountOptionDebug         = uint32(0x001)
	SbMountOptionBsdGroups     = uint32(0x002)
	SbMountOptionXattrUser     = uint32(0x004)
	SbMountOptionACL           = uint32(0x008)
	SbMountOptionUID16         = uint32(0x010)
	SbMountOptionJmodeData     = uint32(0x020)
	SbMountOptionJmodeOrdered  = uint32(0x040)
	SbMountOptionJmodeWback    = uint32(0x060)
	SbMountOptionNoBarrier     = uint32(0x100)
	SbMountOptionBlockValidity = uint32(0x200)
	SbMountOptionDiscard       = uint32(0x400)
	SbMountOptionNoDelAlloc    = uint32(0x800)
)

// Misc. filesystem flags.
const (
	SbFlagSignedDirectoryHash   = uint32(0x1) /* Signed dirhash in use */
	SbFlagUnsignedDirectoryHash = uint32(0x2) /* Unsigned dirhash in use */
	SbFlagTestDevelopmentCode   = uint32(0x4) /* to test development code */
)

// Encryption algorithm.
const (
	SbEncryptAlgoInvalid   = uint8(0)
	SbEncryptAlgoAes256Xt  = uint8(1)
	SbEncryptAlgoAes256Gcm = uint8(2)
	SbEncryptAlgoAes256Cbc = uint8(3)
)

// SuperblockData represents the suberblock stored on disk. See fs/ext4/ext4.h .
type SuperblockData struct {
	// 0x00
	SInodesCount       uint32 /* Inodes count */
	SBlocksCountLo     uint32 /* Blocks count */
	SRBlocksCountLo    uint32 /* Reserved blocks count */
	SFreeBlocksCountLo uint32 /* Free blocks count */

	// 0x10
	SFreeInodesCount uint32 /* Free inodes count */
	SFirstDataBlock  uint32 /* First Data Block */
	SLogBlockSize    uint32 /* Block size */
	SLogClusterSize  uint32 /* Allocation cluster size */

	// 0x20
	SBlocksPerGroup   uint32 /* # Blocks per group */
	SClustersPerGroup uint32 /* # Clusters per group */
	SInodesPerGroup   uint32 /* # Inodes per group */
	SMtime            uint32 /* Mount time */

	// 0x30
	SWtime         uint32 /* Write time */
	SMntCount      uint16 /* Mount count */
	SMaxMntCount   uint16 /* Maximal mount count */
	SMagic         uint16 /* Magic signature */
	SState         uint16 /* File system state */
	SErrors        uint16 /* Behaviour when detecting errors */
	SMinorRevLevel uint16 /* minor revision level */

	// 0x40
	SLastcheck     uint32 /* time of last check */
	SCheckinterval uint32 /* max. time between checks */
	SCreatorOs     uint32 /* OS */
	SRevLevel      uint32 /* Revision level */

	// 0x50
	SDefResuid uint16 /* Default uid for reserved blocks */
	SDefResgid uint16 /* Default gid for reserved blocks */

	// The below is present only if (`HasExtended()` == true).

	/*
	 * These fields are for EXT4_DYNAMIC_REV superblocks only.
	 *
	 * Note: the difference between the compatible feature set and
	 * the incompatible feature set is that if there is a bit set
	 * in the incompatible feature set that the kernel doesn't
	 * know about, it should refuse to mount the filesystem.
	 *
	 * e2fsck's requirements are more strict; if it doesn't know
	 * about a feature in either the compatible or incompatible
	 * feature set, it must abort and not try to meddle with
	 * things it doesn't understand...
	 */
	SFirstIno      uint32 /* First non-reserved inode */
	SInodeSize     uint16 /* size of inode structure */
	SBlockGroupNr  uint16 /* block group # of this superblock */
	SFeatureCompat uint32 /* compatible feature set */

	// 0x60
	SFeatureIncompat uint32 /* incompatible feature set */
	SFeatureRoCompat uint32 /* readonly-compatible feature set */

	// 0x68
	SUuid [16]uint8 /* 128-bit uuid for volume */

	// 0x78
	SVolumeName [16]byte /* volume name */

	// 0x88
	SLastMounted [64]byte /* directory where last mounted */

	// 0xC8
	SAlgorithmUsageBitmap uint32 /* For compression */

	/*
	 * Performance hints.  Directory preallocation should only
	 * happen if the EXT4_FEATURE_COMPAT_DIR_PREALLOC flag is on.
	 */
	SPreallocBlocks    uint8  /* Nr of blocks to try to preallocate*/
	SPreallocDirBlocks uint8  /* Nr to preallocate for dirs */
	SReservedGdtBlocks uint16 /* Per group desc for online growth */

	// 0xD0
	/*
	 * Journaling support valid if EXT4_FEATURE_COMPAT_HAS_JOURNAL set.
	 */
	SJournalUUID [16]uint8 /* uuid of journal superblock */

	// 0xE0
	SJournalInum    uint32    /* inode number of journal file */
	SJournalDev     uint32    /* device number of journal file */
	SLastOrphan     uint32    /* start of list of inodes to delete */
	SHashSeed       [4]uint32 /* HTREE hash seed */
	SDefHashVersion uint8     /* Default hash version to use */
	SJnlBackupType  uint8
	SDescSize       uint16 /* Size of group descriptors, in bytes, if the 64bit incompat feature flag is set. */

	// 0x100
	SDefaultMountOpts uint32
	SFirstMetaBg      uint32     /* First metablock block group */
	SMkfsTime         uint32     /* When the filesystem was created */
	SJnlBlocks        [17]uint32 /* Backup of the journal inode */

	// TODO(dustin): Only if EXT4_FEATURE_COMPAT_64BIT.

	/* 64bit support valid if EXT4_FEATURE_COMPAT_64BIT */

	// 0x150
	SBlocksCountHi     uint32 /* Blocks count */
	SRBlocksCountHi    uint32 /* Reserved blocks count */
	SFreeBlocksCountHi uint32 /* Free blocks count */
	SMinExtraIsize     uint16 /* All inodes have at least # bytes */
	SWantExtraIsize    uint16 /* New inodes should reserve # bytes */

	SFlags            uint32 /* Miscellaneous flags */
	SRaidStride       uint16 /* RAID stride */
	SMmpInterval      uint16 /* # seconds to wait in MMP checking */
	SMmpBlock         uint64 /* Block for multi-mount protection */
	SRaidStripeWidth  uint32 /* blocks on all data disks (N*stride)*/
	SLogGroupsPerFlex uint8  /* FLEX_BG group size */
	SChecksumType     uint8  /* metadata checksum algorithm used */
	SEncryptionLevel  uint8  /* versioning level for encryption */
	SReservedPad      uint8  /* Padding to next 32bits */
	SKbytesWritten    uint64 /* nr of lifetime kilobytes written */

	SSnapshotInum         uint32 /* Inode number of active snapshot */
	SSnapshotID           uint32 /* sequential ID of active snapshot */
	SSnapshotRBlocksCount uint64 /* reserved blocks for active snapshot's future use */
	SSnapshotList         uint32 /* inode number of the head of the on-disk snapshot list */

	SErrorCount      uint32    /* number of fs errors */
	SFirstErrorTime  uint32    /* first time an error happened */
	SFirstErrorIno   uint32    /* inode involved in first error */
	SFirstErrorBlock uint64    /* block involved of first error */
	SFirstErrorFunc  [32]uint8 /* function where the error happened */
	SFirstErrorLine  uint32    /* line number where error happened */
	SLastErrorTime   uint32    /* most recent time of an error */
	SLastErrorIno    uint32    /* inode involved in last error */
	SLastErrorLine   uint32    /* line number where error happened */
	SLastErrorBlock  uint64    /* block involved of last error */
	SLastErrorFunc   [32]uint8 /* function where the error happened */

	SMountOpts        [64]uint8
	SUsrQuotaInum     uint32    /* inode for tracking user quota */
	SGrpQuotaInum     uint32    /* inode for tracking group quota */
	SOverheadClusters uint32    /* overhead blocks/clusters in fs */
	SBackupBgs        [2]uint32 /* groups with sparse_super2 SBs */
	SEncryptAlgos     [4]uint8  /* Encryption algorithms in use  */
	SEncryptPwSalt    [16]uint8 /* Salt used for string2key algorithm */
	SLpfIno           uint32    /* Location of the lost+found inode */
	SPrjQuotaInum     uint32    /* inode for tracking project quota */
	SChecksumSeed     uint32    /* crc32c(uuid) if csum_seed set */
	SWtimeHi          uint8
	SMtimeHi          uint8
	SMkfsTimeHi       uint8
	SLastcheckHi      uint8
	SFirstErrorTimeHi uint8
	SLastErrorTimeHi  uint8
	SPad              [2]uint8
	SReserved         [96]uint32 /* Padding to the end of the block */
	SChecksum         int32      /* crc32c(superblock) */
}

// Superblock is a wrapper around SuperblockData with the io.Reader .
type Superblock struct {
	data      *SuperblockData
	blockSize uint32
	is64Bit   bool
	rs        io.ReadSeeker
}

// Data is the getter for Superblock.data .
func (sb *Superblock) Data() *SuperblockData {
	return sb.data
}

// NewSuperblockWithReader reads the superblock from device and initializes the
// Superblock struct.
func NewSuperblockWithReader(rs io.ReadSeeker) (sb *Superblock, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	sbd := new(SuperblockData)

	err = binary.Read(rs, binary.LittleEndian, sbd)
	if err != nil {
		panic(err)
	}

	if sbd.SMagic != Ext4Magic {
		log.Panic(ErrNotExt4)
	}

	blockSize := uint32(math.Pow(2, 10+float64(sbd.SLogBlockSize)))

	sb = &Superblock{
		data:      sbd,
		blockSize: blockSize,
		rs:        rs,
	}

	sb.is64Bit = sb.HasIncompatibleFeature(SbFeatureIncompat64bit)

	// Assert our present operating assumptions in order to stabilize development.

	if sb.HasIncompatibleFeature(SbFeatureIncompatMetaBg) == true {
		log.Panicf("meta_bg feature not supported")
	} else if sb.HasIncompatibleFeature(SbFeatureIncompatFlexBg) == false {
		log.Panicf("only filesystems with flex_bg are supported")
	} else if sb.HasIncompatibleFeature(SbFeatureIncompatCompression) == true {
		log.Panicf("only uncompressed filesystems are supported")
	} else if sb.HasIncompatibleFeature(SbFeatureIncompatFiletype) == false {
		log.Panicf("only directory-entries with a filetype are supported")
	} else if sb.HasIncompatibleFeature(SbFeatureIncompatExtents) == false {
		log.Panicf("only filesystems using extents are supported")
	} else if sb.HasIncompatibleFeature(SbFeatureIncompatDirData) == true {
		log.Panicf("dir-data is obscure and not supported")
	} else if sb.HasIncompatibleFeature(SbFeatureIncompatJournalDev) == true {
		log.Panicf("external journal devices are not supported")
	} else if sb.HasIncompatibleFeature(SbFeatureIncompatLargeDir) == true {
		log.Panicf("large-dirs are not supported")
	} else if sb.HasIncompatibleFeature(SbFeatureIncompatInlineData) == true {
		// Data may be stored directly in the inode for small files.

		log.Panicf("inline-data not supported")
	} else if sb.HasIncompatibleFeature(SbFeatureIncompatEncrypt) == true {
		log.Panicf("encrypted filesystems not supported")
	}

	// SbFeatureIncompatRecover: Ignoring because it presumably doesn't matter
	// when not writing.

	// SbFeatureIncompatMmp: Ignoring because we're not involved in mounting
	// (and not writing, besides).

	// SbFeatureIncompatLargeExtendedAttributeValues: Ignoring because we don't
	// currently read xattr's.

	// SbFeatureIncompatCsumSeed: Ignoring because we're not concerned with
	// mount semantics.

	return sb, nil
}

// HasExtended returns true if the fs supports dynamic inode sizes.
func (sb *Superblock) HasExtended() bool {
	return sb.data.SRevLevel >= SbRevlevelDynamicRev
}

// BlockSize is the getter for Superblock.blockSize .
func (sb *Superblock) BlockSize() uint32 {
	return sb.blockSize
}

// MountTime gets and returns the mount time as time.Time object.
func (sb *Superblock) MountTime() time.Time {
	return time.Unix(int64(sb.data.SMtime), 0)
}

// WriteTime gets and returns the write time as time.Time object.
func (sb *Superblock) WriteTime() time.Time {
	return time.Unix(int64(sb.data.SWtime), 0)
}

// LastCheckTime gets and returns time of last check as time.Time object.
func (sb *Superblock) LastCheckTime() time.Time {
	return time.Unix(int64(sb.data.SLastcheck), 0)
}

// VolumeName returns the volume name as a string.
func (sb *Superblock) VolumeName() string {
	volumeName := string(sb.data.SVolumeName[:])
	volumeName = strings.TrimRight(volumeName, "\000")

	return volumeName
}

// Is64Bit is a getter for Superblock.is64Bit .
func (sb *Superblock) Is64Bit() bool {
	return sb.is64Bit
}

// HasCompatibleFeature returns true is ths fs supports the feature represented
// by the mask.
func (sb *Superblock) HasCompatibleFeature(mask uint32) bool {
	return (sb.data.SFeatureCompat & mask) > 0
}

// HasReadonlyCompatibleFeature returns true when the feature represented by
// the mask belongs to the readonly-compatible feature set.
func (sb *Superblock) HasReadonlyCompatibleFeature(mask uint32) bool {
	return (sb.data.SFeatureRoCompat & mask) > 0
}

// HasIncompatibleFeature returns true when the feature represented by
// the mask belongs to the incompatible feature set.
func (sb *Superblock) HasIncompatibleFeature(mask uint32) bool {
	return (sb.data.SFeatureIncompat & mask) > 0
}

// TODO(dustin): !! Make our ints into uint64s.

// BlockGroupNumberWithAbsoluteInodeNumber returns the block number in which
// the given inode belongs.
func (sb *Superblock) BlockGroupNumberWithAbsoluteInodeNumber(absoluteInodeNumber int) int {
	return (absoluteInodeNumber - 1) / int(sb.data.SInodesPerGroup)
}

// BlockGroupInodeNumberWithAbsoluteInodeNumber converts an absolute inode
// number block group inode number (inode number within a group).
func (sb *Superblock) BlockGroupInodeNumberWithAbsoluteInodeNumber(absoluteInodeNumber int) int {
	return (absoluteInodeNumber - 1) % int(sb.data.SInodesPerGroup)
}

// ReadPhysicalBlock reads `length` bytes from the block indicated by the absolute block number.
func (sb *Superblock) ReadPhysicalBlock(absoluteBlockNumber uint64, length uint64) (data []byte, err error) {
	if length > uint64(sb.blockSize) {
		log.Panicf("can't read more bytes (%d) than block-size (%d)", length, sb.blockSize)
	}

	offset := absoluteBlockNumber * uint64(sb.blockSize)

	_, err = sb.rs.Seek(int64(offset), io.SeekStart)
	if err != nil {
		panic(err)
	}

	data = make([]byte, length)

	_, err = sb.rs.Read(data)
	if err != nil {
		panic(err)
	}

	return data, nil
}

// FreeBlockCount returns the number of free data blocks in the fs.
func (sb *Superblock) FreeBlockCount() uint64 {
	if sb.is64Bit == true {
		return (uint64(sb.data.SFreeBlocksCountHi) << 32) | uint64(sb.data.SFreeBlocksCountLo)
	}

	return uint64(sb.data.SFreeBlocksCountLo)
}

// BlockCount returns the number of blocks in the fs.
func (sb *Superblock) BlockCount() uint64 {
	if sb.is64Bit == true {
		return (uint64(sb.data.SBlocksCountHi) << 32) | uint64(sb.data.SBlocksCountLo)
	}

	return uint64(sb.data.SBlocksCountLo)
}

// BlockGroupCount is the number of block groups in the fs.
func (sb *Superblock) BlockGroupCount() (blockGroups uint64) {
	blockGroups = sb.BlockCount() / uint64(sb.data.SBlocksPerGroup)

	// If we have less than one block-group's worth of blocks.
	if blockGroups == 0 {
		blockGroups = 1
	}

	return blockGroups
}

// Dump prints out the contents of the superblock.
func (sb *Superblock) Dump() {
	fmt.Printf("Superblock Info\n")
	fmt.Printf("\n")

	fmt.Printf("SInodesCount: (%d)\n", sb.data.SInodesCount)
	fmt.Printf("SBlocksCountLo: (%d)\n", sb.data.SBlocksCountLo)
	fmt.Printf("SRBlocksCountLo: (%d)\n", sb.data.SRBlocksCountLo)
	fmt.Printf("SFreeBlocksCountLo: (%d)\n", sb.data.SFreeBlocksCountLo)
	fmt.Printf("SFreeInodesCount: (%d)\n", sb.data.SFreeInodesCount)
	fmt.Printf("SFirstDataBlock: (%d)\n", sb.data.SFirstDataBlock)
	fmt.Printf("SLogBlockSize: (%d) => (%d)\n", sb.data.SLogBlockSize, sb.BlockSize())
	fmt.Printf("SLogClusterSize: (%d)\n", sb.data.SLogClusterSize)
	fmt.Printf("SBlocksPerGroup: (%d)\n", sb.data.SBlocksPerGroup)
	fmt.Printf("SClustersPerGroup: (%d)\n", sb.data.SClustersPerGroup)
	fmt.Printf("SInodesPerGroup: (%d)\n", sb.data.SInodesPerGroup)
	fmt.Printf("SMtime: [%s]\n", sb.MountTime())
	fmt.Printf("SWtime: [%s]\n", sb.WriteTime())
	fmt.Printf("SMntCount: (%d)\n", sb.data.SMntCount)
	fmt.Printf("SMaxMntCount: (%d)\n", sb.data.SMaxMntCount)
	fmt.Printf("SMagic: [%04x]\n", sb.data.SMagic)
	fmt.Printf("SState: (%04x)\n", sb.data.SState)
	fmt.Printf("SErrors: (%d)\n", sb.data.SErrors)
	fmt.Printf("SMinorRevLevel: (%d)\n", sb.data.SMinorRevLevel)
	fmt.Printf("SLastcheck: [%s]\n", sb.LastCheckTime())
	fmt.Printf("SCheckinterval: (%d)\n", sb.data.SCheckinterval)
	fmt.Printf("SCreatorOs: (%d)\n", sb.data.SCreatorOs)
	fmt.Printf("SRevLevel: (%d)\n", sb.data.SRevLevel)
	fmt.Printf("SDefResuid: (%d)\n", sb.data.SDefResuid)
	fmt.Printf("SDefResgid: (%d)\n", sb.data.SDefResgid)

	// TODO(dustin): Finish.

	fmt.Printf("SDescSize: (%d)\n", sb.data.SDescSize)
	fmt.Printf("SLogGroupsPerFlex: (%d)\n", sb.data.SLogGroupsPerFlex)
	fmt.Printf("SInodeSize: (%d)\n", sb.data.SInodeSize)

	fmt.Printf("BlockCount: (%d)\n", sb.BlockCount())
	fmt.Printf("BlockGroupCount: (%d)\n", sb.BlockGroupCount())
	fmt.Printf("SBlocksPerGroup: (%d)\n", sb.data.SBlocksPerGroup)

	fmt.Printf("\n")

	sb.DumpFeatures(false)
}

// DumpFeatures prints out al the features (compatible, read-only and
// incompatible) of the fs.
func (sb *Superblock) DumpFeatures(includeFalses bool) {
	fmt.Printf("Features (Compatible)\n")
	fmt.Printf("\n")

	for _, name := range SbFeatureCompatNames {
		bit := SbFeatureCompatLookup[name]
		value := sb.HasCompatibleFeature(bit)

		if includeFalses == true || value == true {
			fmt.Printf("  %15s (0x%02x): %v\n", name, bit, value)
		}
	}

	fmt.Printf("\n")

	fmt.Printf("Features (Read-Only Compatible)\n")
	fmt.Printf("\n")

	for _, name := range SbFeatureRoCompatNames {
		bit := SbFeatureRoCompatLookup[name]
		value := sb.HasReadonlyCompatibleFeature(bit)

		if includeFalses == true || value == true {
			fmt.Printf("  %15s (0x%02x): %v\n", name, bit, value)
		}
	}

	fmt.Printf("\n")

	fmt.Printf("Features (Incompatible)\n")
	fmt.Printf("\n")

	for _, name := range SbFeatureIncompatNames {
		bit := SbFeatureIncompatLookup[name]
		value := sb.HasIncompatibleFeature(bit)

		if includeFalses == true || value == true {
			fmt.Printf("  %15s (0x%02x): %v\n", name, bit, value)
		}
	}

	fmt.Printf("\n")
}

// Compatible feature set definitions.
const (
	// COMPAT_DIR_PREALLOC
	SbFeatureCompatDirPrealloc = uint32(0x0001)

	// COMPAT_IMAGIC_INODES
	SbFeatureCompatImagicInodes = uint32(0x0002)

	// COMPAT_HAS_JOURNAL
	SbFeatureCompatHasJournal = uint32(0x0004)

	// COMPAT_EXT_ATTR
	SbFeatureCompatExtAttr = uint32(0x0008)

	// COMPAT_RESIZE_INODE
	SbFeatureCompatResizeInode = uint32(0x0010)

	// COMPAT_DIR_INDEX
	SbFeatureCompatDirIndex = uint32(0x0020)

	// COMPAT_LAZY_BG
	SbFeatureCompatLazyBg = uint32(0x40)

	// COMPAT_EXCLUDE_INODE
	SbFeatureCompatExcludeInode = uint32(0x80)

	// COMPAT_EXCLUDE_BITMAP
	SbFeatureCompatExcludeBitmap = uint32(0x100)

	// COMPAT_SPARSE_SUPER2
	SbFeatureCompatSparseSuperblockV2 = uint32(0x200)
)

var (
	// SbFeatureCompatNames is an ordered list of names.
	SbFeatureCompatNames = []string{
		"DirIndex",
		"DirPrealloc",
		"ExcludeBitmap",
		"ExcludeInode",
		"ExtAttr",
		"HasJournal",
		"ImagicInodes",
		"LazyBg",
		"ResizeInode",
		"SparseSuper2",
	}

	// SbFeatureCompatLookup maps the string description of ext4 compatible
	// feature to its feature mask.
	SbFeatureCompatLookup = map[string]uint32{
		"DirPrealloc":   SbFeatureCompatDirPrealloc,
		"ImagicInodes":  SbFeatureCompatImagicInodes,
		"HasJournal":    SbFeatureCompatHasJournal,
		"ExtAttr":       SbFeatureCompatExtAttr,
		"ResizeInode":   SbFeatureCompatResizeInode,
		"DirIndex":      SbFeatureCompatDirIndex,
		"LazyBg":        SbFeatureCompatLazyBg,
		"ExcludeInode":  SbFeatureCompatExcludeInode,
		"ExcludeBitmap": SbFeatureCompatExcludeBitmap,
		"SparseSuper2":  SbFeatureCompatSparseSuperblockV2,
	}
)

// Read-only feature set definitions.
const (
	// RO_COMPAT_SPARSE_SUPER
	SbFeatureRoCompatSparseSuper = uint32(0x1)

	// RO_COMPAT_LARGE_FILE
	SbFeatureRoCompatLargeFile = uint32(0x2)

	// RO_COMPAT_BTREE_DIR
	SbFeatureRoCompatBtreeDir = uint32(0x4)

	// RO_COMPAT_HUGE_FILE
	SbFeatureRoCompatHugeFile = uint32(0x8)

	// RO_COMPAT_GDT_CSUM
	SbFeatureRoCompatGdtCsum = uint32(0x10)

	// RO_COMPAT_DIR_NLINK
	SbFeatureRoCompatDirNlink = uint32(0x20)

	// RO_COMPAT_EXTRA_ISIZE
	SbFeatureRoCompatExtraIsize = uint32(0x40)

	// RO_COMPAT_HAS_SNAPSHOT
	SbFeatureRoCompatHasSnapshot = uint32(0x80)

	// RO_COMPAT_QUOTA
	SbFeatureRoCompatQuota = uint32(0x100)

	// RO_COMPAT_BIGALLOC
	SbFeatureRoCompatBigAlloc = uint32(0x200)

	// RO_COMPAT_METADATA_CSUM
	SbFeatureRoCompatMetadataCsum = uint32(0x400)

	// RO_COMPAT_REPLICA
	SbFeatureRoCompatReplica = uint32(0x800)

	// RO_COMPAT_READONLY
	SbFeatureRoCompatReadonly = uint32(0x1000)

	// RO_COMPAT_PROJECT
	SbFeatureRoCompatProject = uint32(0x2000)
)

var (
	// SbFeatureRoCompatNames is an ordered list of names.
	SbFeatureRoCompatNames = []string{
		"BigAlloc",
		"BtreeDir",
		"DirNlink",
		"ExtraIsize",
		"GdtCsum",
		"HasSnapshot",
		"HugeFile",
		"LargeFile",
		"MetadataCsum",
		"Project",
		"Quota",
		"Readonly",
		"Replica",
		"SparseSuper",
	}

	// SbFeatureRoCompatLookup maps the string description of ext4 read only
	// feature to its feature mask.
	SbFeatureRoCompatLookup = map[string]uint32{
		"SparseSuper":  SbFeatureRoCompatSparseSuper,
		"LargeFile":    SbFeatureRoCompatLargeFile,
		"BtreeDir":     SbFeatureRoCompatBtreeDir,
		"HugeFile":     SbFeatureRoCompatHugeFile,
		"GdtCsum":      SbFeatureRoCompatGdtCsum,
		"DirNlink":     SbFeatureRoCompatDirNlink,
		"ExtraIsize":   SbFeatureRoCompatExtraIsize,
		"HasSnapshot":  SbFeatureRoCompatHasSnapshot,
		"Quota":        SbFeatureRoCompatQuota,
		"BigAlloc":     SbFeatureRoCompatBigAlloc,
		"MetadataCsum": SbFeatureRoCompatMetadataCsum,
		"Replica":      SbFeatureRoCompatReplica,
		"Readonly":     SbFeatureRoCompatReadonly,
		"Project":      SbFeatureRoCompatProject,
	}
)

// Incompatible feature set definitions.
const (
	// INCOMPAT_COMPRESSION
	SbFeatureIncompatCompression = uint32(0x0001)

	// INCOMPAT_FILETYPE
	SbFeatureIncompatFiletype = uint32(0x0002)

	// INCOMPAT_RECOVER
	SbFeatureIncompatRecover = uint32(0x0004) /* Needs recovery */

	// INCOMPAT_JOURNAL_DEV
	SbFeatureIncompatJournalDev = uint32(0x0008) /* Journal device */

	// INCOMPAT_META_BG
	SbFeatureIncompatMetaBg = uint32(0x0010)

	// INCOMPAT_EXTENTS
	SbFeatureIncompatExtents = uint32(0x0040) /* extents support */

	// INCOMPAT_64BIT
	SbFeatureIncompat64bit = uint32(0x0080)

	// INCOMPAT_MMP
	SbFeatureIncompatMmp = uint32(0x0100)

	// INCOMPAT_FLEX_BG
	SbFeatureIncompatFlexBg = uint32(0x0200)

	// INCOMPAT_EA_INODE
	SbFeatureIncompatLargeExtendedAttributeValues = uint32(0x400)

	// INCOMPAT_DIRDATA
	SbFeatureIncompatDirData = uint32(0x1000)

	// INCOMPAT_CSUM_SEED
	SbFeatureIncompatCsumSeed = uint32(0x2000)

	// INCOMPAT_LARGEDIR
	SbFeatureIncompatLargeDir = uint32(0x4000)

	// INCOMPAT_INLINE_DATA
	SbFeatureIncompatInlineData = uint32(0x8000)

	// INCOMPAT_ENCRYPT
	SbFeatureIncompatEncrypt = uint32(0x10000)
)

var (
	// SbFeatureIncompatNames is an ordered list of names.
	SbFeatureIncompatNames = []string{
		"64bit",
		"Compression",
		"CsumSeed",
		"DirData",
		"Encrypt",
		"Extents",
		"Filetype",
		"FlexBg",
		"InlineData",
		"JournalDev",
		"LargeDir",
		"LargeExtendedAttributeValues",
		"MetaBg",
		"Mmp",
		"Recover",
	}

	// SbFeatureIncompatLookup maps the string description of ext4 incompatible
	// feature to its feature mask.
	SbFeatureIncompatLookup = map[string]uint32{
		"Compression":                  SbFeatureIncompatCompression,
		"Filetype":                     SbFeatureIncompatFiletype,
		"Recover":                      SbFeatureIncompatRecover,
		"JournalDev":                   SbFeatureIncompatJournalDev,
		"MetaBg":                       SbFeatureIncompatMetaBg,
		"Extents":                      SbFeatureIncompatExtents,
		"64bit":                        SbFeatureIncompat64bit,
		"Mmp":                          SbFeatureIncompatMmp,
		"FlexBg":                       SbFeatureIncompatFlexBg,
		"LargeExtendedAttributeValues": SbFeatureIncompatLargeExtendedAttributeValues,
		"DirData":                      SbFeatureIncompatDirData,
		"CsumSeed":                     SbFeatureIncompatCsumSeed,
		"LargeDir":                     SbFeatureIncompatLargeDir,
		"InlineData":                   SbFeatureIncompatInlineData,
		"Encrypt":                      SbFeatureIncompatEncrypt,
	}
)
