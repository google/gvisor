package goext4

import (
	"fmt"
	"io"
	"log"
	"sort"
	"time"

	"encoding/binary"
)

// Reserved inode numbers.
const (
	InodeDefectiveBlocks          = 1
	InodeRootDirectory            = 2
	InodeUserQuota                = 3
	InodeGroupQuota               = 4
	InodeBootLoader               = 5
	InodeUndeleteDirectory        = 6
	InodeReservedGroupDescriptors = 7
	InodeJournal                  = 8
	InodeExclude                  = 9
	InodeReplica                  = 10
)

// Constants relative to the data blocks.
const (
	Ext4NdirBlocks = 12
	Ext4IndBlock   = Ext4NdirBlocks
	Ext4DindBlock  = (Ext4IndBlock + 1)
	Ext4TindBlock  = (Ext4DindBlock + 1)
	Ext4NBlocks    = (Ext4TindBlock + 1)
)

// Inode flags.
const (
	InodeFlagSecrm           = 0x1
	InodeFlagUnrm            = 0x2
	InodeFlagCompr           = 0x4
	InodeFlagSync            = 0x8
	InodeFlagImmutable       = 0x10
	InodeFlagAppend          = 0x20
	InodeFlagNodump          = 0x40
	InodeFlagNoatime         = 0x80
	InodeFlagDirty           = 0x100
	InodeFlagComprblk        = 0x200
	InodeFlagNocompr         = 0x400
	InodeFlagEncrypt         = 0x800
	InodeFlagIndex           = 0x1000
	InodeFlagImagic          = 0x2000
	InodeFlagJournalData     = 0x4000
	InodeFlagNotail          = 0x8000
	InodeFlagDirsync         = 0x10000
	InodeFlagTopdir          = 0x20000
	InodeFlagHugeFile        = 0x40000
	InodeFlagExtents         = 0x80000
	InodeFlagEaInode         = 0x200000
	InodeFlagEofblocks       = 0x400000
	InodeFlagSnapfile        = 0x01000000
	InodeFlagSnapfileDeleted = 0x04000000
	InodeFlagSnapfileShrunk  = 0x08000000
	InodeFlagInlineData      = 0x10000000
	InodeFlagProjinherit     = 0x20000000
)

// Mapping from string rep of flags to hex values.
var (
	InodeFlagLookup = map[string]int{
		"Secrm":           InodeFlagSecrm,
		"Unrm":            InodeFlagUnrm,
		"Compr":           InodeFlagCompr,
		"Sync":            InodeFlagSync,
		"Immutable":       InodeFlagImmutable,
		"Append":          InodeFlagAppend,
		"Nodump":          InodeFlagNodump,
		"Noatime":         InodeFlagNoatime,
		"Dirty":           InodeFlagDirty,
		"Comprblk":        InodeFlagComprblk,
		"Nocompr":         InodeFlagNocompr,
		"Encrypt":         InodeFlagEncrypt,
		"Index":           InodeFlagIndex,
		"Imagic":          InodeFlagImagic,
		"JournalData":     InodeFlagJournalData,
		"Notail":          InodeFlagNotail,
		"Dirsync":         InodeFlagDirsync,
		"Topdir":          InodeFlagTopdir,
		"HugeFile":        InodeFlagHugeFile,
		"Extents":         InodeFlagExtents,
		"EaInode":         InodeFlagEaInode,
		"Eofblocks":       InodeFlagEofblocks,
		"Snapfile":        InodeFlagSnapfile,
		"SnapfileDeleted": InodeFlagSnapfileDeleted,
		"SnapfileShrunk":  InodeFlagSnapfileShrunk,
		"InlineData":      InodeFlagInlineData,
		"Projinherit":     InodeFlagProjinherit,
	}
)

// InodeData represents the structure of an inode on the disk.
type InodeData struct {
	IMode       uint16 /* File mode */
	IUid        uint16 /* Low 16 bits of Owner Uid */
	ISizeLo     uint32 /* Size in bytes */
	IAtime      uint32 /* Access time */
	ICtime      uint32 /* Inode Change time */
	IMtime      uint32 /* Modification time */
	IDtime      uint32 /* Deletion Time */
	IGid        uint16 /* Low 16 bits of Group Id */
	ILinksCount uint16 /* Links count */
	IBlocksLo   uint32 /* Blocks count */
	IFlags      uint32 /* File flags */

	// union {
	//     struct {
	//         __le32  l_i_version;
	//     } linux1;
	//     struct {
	//         __u32  h_i_translator;
	//     } hurd1;
	//     struct {
	//         __u32  m_i_reserved1;
	//     } masix1;
	// } osd1;             /* OS dependent 1 */
	Osd1 [4]byte

	/*
		IBlock is a general buffer for our data, which can have various
		interpretations. `Ext4NBlocks` comes from the kernel where it is a count in
		terms of uint32's, which is then cast as a struct. However, it works better
		for us as an array of bytes.
	*/
	IBlock [Ext4NBlocks * 4]byte

	IGeneration uint32 /* File version (for NFS) */
	IFileACLLo  uint32 /* File ACL */
	ISizeHigh   uint32
	IObsoFaddr  uint32 /* Obsoleted fragment address */

	// union {
	//     struct {
	//         __le16  l_i_blocks_high; /* were l_i_reserved1 */
	//         __le16  l_i_file_acl_high;
	//         __le16  l_i_uid_high;   /* these 2 fields */
	//         __le16  l_i_gid_high;   /* were reserved2[0] */
	//         __le16  l_i_checksum_lo;/* crc32c(uuid+inum+inode) LE */
	//         __le16  l_i_reserved;
	//     } linux2;
	//     struct {
	//         __le16  h_i_reserved1;   Obsoleted fragment number/size which are removed in ext4
	//         __u16   h_i_mode_high;
	//         __u16   h_i_uid_high;
	//         __u16   h_i_gid_high;
	//         __u32   h_i_author;
	//     } hurd2;
	//     struct {
	//         __le16  h_i_reserved1;  /* Obsoleted fragment number/size which are removed in ext4 */
	//         __le16  m_i_file_acl_high;
	//         __u32   m_i_reserved2[2];
	//     } masix2;
	// } osd2;             /* OS dependent 2 */
	Osd2 [12]byte

	IExtraIsize  uint16
	IChecksumHi  uint16 /* crc32c(uuid+inum+inode) BE */
	ICtimeExtra  uint32 /* extra Change time      (nsec << 2 | epoch) */
	IMtimeExtra  uint32 /* extra Modification time(nsec << 2 | epoch) */
	IAtimeExtra  uint32 /* extra Access time      (nsec << 2 | epoch) */
	ICrtime      uint32 /* File Creation time */
	ICrtimeExtra uint32 /* extra FileCreationtime (nsec << 2 | epoch) */
	IVersionHi   uint32 /* high 32 bits for 64-bit version */
	IProjid      uint32 /* Project ID */
}

// Inode wraps InodeData which actually exists on disk and a point to the
// block group descriptor which contains the inode.
type Inode struct {
	data *InodeData
	bgd  *BlockGroupDescriptor
}

func (inode *Inode) String() string {
	return fmt.Sprintf("Inode<>")
}

// BlockGroupDescriptor is a getter for Inode.bgd .
func (inode *Inode) BlockGroupDescriptor() (bgd *BlockGroupDescriptor) {
	return inode.bgd
}

// NewInodeWithReadSeeker read in an Inode from the underlying device and returns it.
func NewInodeWithReadSeeker(bgd *BlockGroupDescriptor, rs io.ReadSeeker, absoluteInodeNumber int) (inode *Inode, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	// TODO(dustin): !! We might want to find a way to verify this against the bitmap if we can pre-store it in the BGD.
	// func (bgd *BlockGroupDescriptor) InodeBitmapBlock() uint64 {

	sb := bgd.Superblock()

	absoluteInodeTableBlock := bgd.InodeTableBlock()
	offset := uint64(sb.BlockSize()) * absoluteInodeTableBlock

	// bgRelativeInode is the number of the inode within the inode-table for
	// this particular block-group. The math only makes sense if we take
	// (inode - 1) since there is no "inode 0".
	bgRelativeInode := (uint64(absoluteInodeNumber) - 1) % uint64(sb.Data().SInodesPerGroup)

	offset += bgRelativeInode * uint64(sb.Data().SInodeSize)

	_, err = rs.Seek(int64(offset), io.SeekStart)
	if err != nil {
		panic(err)
	}

	id := new(InodeData)

	err = binary.Read(rs, binary.LittleEndian, id)
	if err != nil {
		panic(err)
	}

	inode = &Inode{
		data: id,
		bgd:  bgd,
	}

	// Assert our present operating assumptions in order to stabilize
	// development.

	if inode.Flag(InodeFlagIndex) == true {
		// TODO(dustin): Might be present in large directories. We might need to implement both mechanisms (this and "linear directories").
		log.Panicf("hash-tree directories not currently supported")
	} else if inode.Flag(InodeFlagExtents) == false {
		log.Panicf("only inodes having extent trees are supported")
	}

	return inode, nil
}

// Data is the getter for Inode.data .
func (inode *Inode) Data() *InodeData {
	return inode.data
}

// AccessTime is the getter for Inode.data.IAtime .
func (inode *Inode) AccessTime() time.Time {
	return time.Unix(int64(inode.data.IAtime), 0)
}

// InodeChangeTime is the getter for Inode.data.ICtime .
func (inode *Inode) InodeChangeTime() time.Time {
	return time.Unix(int64(inode.data.ICtime), 0)
}

// ModificationTime is the getter for Inode.data.IMtime .
func (inode *Inode) ModificationTime() time.Time {
	return time.Unix(int64(inode.data.IMtime), 0)
}

// DeletionTime is the getter for Inode.data.IDtime .
func (inode *Inode) DeletionTime() time.Time {
	return time.Unix(int64(inode.data.IDtime), 0)
}

// FileCreationTime is the getter for Inode.data.ICrtime .
func (inode *Inode) FileCreationTime() time.Time {
	return time.Unix(int64(inode.data.ICrtime), 0)
}

// Size is the same as ext4_isize in linux which returns the inode size.
func (inode *Inode) Size() uint64 {
	return (uint64(inode.data.ISizeHigh) << 32) | uint64(inode.data.ISizeLo)
}

// Flag returns true if the passed in flag is set.
func (inode *Inode) Flag(flag int) bool {
	return (inode.data.IFlags & uint32(flag)) > 0
}

// Links returns the number of hard links.
func (inode *Inode) Links() uint16 {
	return inode.data.ILinksCount
}

// Dump prints out inode details contains in InodeData.
func (inode *Inode) Dump() {
	defer func() {
		if state := recover(); state != nil {
			log.Panic(WrapError(state))
		}
	}()

	fmt.Printf("IAtime: [%s]\n", inode.AccessTime())
	fmt.Printf("ICtime: [%s]\n", inode.InodeChangeTime())
	fmt.Printf("IMtime: [%s]\n", inode.ModificationTime())
	fmt.Printf("IDtime: [%s]\n", inode.DeletionTime())
	fmt.Printf("ICrtime: [%s]\n", inode.FileCreationTime())

	// TODO(dustin): !! Print the rest of the fields.

}

// DumpFlags prints all the flags which are set.
func (inode *Inode) DumpFlags(includeFalses bool) {
	defer func() {
		if state := recover(); state != nil {
			log.Panic(WrapError(state))
		}
	}()

	fmt.Printf("\n")
	fmt.Printf("Flags:\n")
	fmt.Printf("\n")

	names := make([]string, len(InodeFlagLookup))
	i := 0
	for name := range InodeFlagLookup {
		names[i] = name
		i++
	}

	sort.Strings(names)

	for _, name := range names {
		bit := InodeFlagLookup[name]
		value := inode.Flag(bit)

		if includeFalses == true || value == true {
			fmt.Printf("%s: %v\n", name, value)
		}
	}

	fmt.Printf("\n")
}
