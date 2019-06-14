package goext4

import (
	"fmt"
	"log"
)

// Filesize and direntry sizes. See fs/ext4/ext4.h.
const (
	FilenameMaxLen     = 255
	DirectoryEntrySize = FilenameMaxLen + 8 // sizeof(ext4_dir_entry_2)
)

// File types.
const (
	FileTypeUnknown         = uint8(0x0)
	FileTypeRegular         = uint8(0x1)
	FileTypeDirectory       = uint8(0x2)
	FileTypeCharacterDevice = uint8(0x3)
	FileTypeBlockDevice     = uint8(0x4)
	FileTypeFifo            = uint8(0x5)
	FileTypeSocket          = uint8(0x6)
	FileTypeSymbolicLink    = uint8(0x7)
)

// Maps file types to string description
var (
	FileTypeLookup = map[uint8]string{
		FileTypeUnknown:         "unknown",
		FileTypeRegular:         "regular",
		FileTypeDirectory:       "directory",
		FileTypeCharacterDevice: "character device",
		FileTypeBlockDevice:     "block device",
		FileTypeFifo:            "fifo",
		FileTypeSocket:          "socket",
		FileTypeSymbolicLink:    "symbolic link",
	}
)

// DirEntry2 is one of potentially many sequential entries stored in a
// directory inode.
type DirEntry2 struct {
	Inode    uint32 // Number of the inode that this directory entry points to.
	RecLen   uint16 // Length of this directory entry.
	NameLen  uint8  // Length of the file name.
	FileType uint8  // File type code, see ftype table below.
	Name     []byte // File name. Has a maximum size of FilenameMaxLen but actual length derived from `RecLen`.
}

// DirectoryEntry wraps the raw directory entry and provides higher-level
// functionality.
type DirectoryEntry struct {
	data *DirEntry2
}

// Data is the getter for DirectoryEntry.data .
func (de *DirectoryEntry) Data() *DirEntry2 {
	return de.data
}

// Name returns a slice representing the filename.
func (de *DirectoryEntry) Name() string {
	return string(de.data.Name[:])
}

// IsUnknownType returns true if the file type is unknown.
func (de *DirectoryEntry) IsUnknownType() bool {
	return de.data.FileType == FileTypeUnknown
}

// IsRegular returns true if the file type is regular.
func (de *DirectoryEntry) IsRegular() bool {
	return de.data.FileType == FileTypeRegular
}

// IsDirectory returns true the file is a directory.
func (de *DirectoryEntry) IsDirectory() bool {
	return de.data.FileType == FileTypeDirectory
}

// IsCharacterDevice returns true the file is a character device.
func (de *DirectoryEntry) IsCharacterDevice() bool {
	return de.data.FileType == FileTypeCharacterDevice
}

// IsBlockDevice returns true the file is a block device.
func (de *DirectoryEntry) IsBlockDevice() bool {
	return de.data.FileType == FileTypeBlockDevice
}

// IsFifo returns true the file is a named pipe.
func (de *DirectoryEntry) IsFifo() bool {
	return de.data.FileType == FileTypeFifo
}

// IsSocket returns true the file is a socket.
func (de *DirectoryEntry) IsSocket() bool {
	return de.data.FileType == FileTypeSocket
}

// IsSymbolicLink returns true the file is a symbolic link.
func (de *DirectoryEntry) IsSymbolicLink() bool {
	return de.data.FileType == FileTypeSymbolicLink
}

// TypeName returns the string representation of the file type.
func (de *DirectoryEntry) TypeName() string {
	name, found := FileTypeLookup[de.data.FileType]
	if found == false {
		log.Panicf("invalid type (%d) for inode (%d)", de.data.FileType, de.data.Inode)
	}

	return name
}

func (de *DirectoryEntry) String() string {
	return fmt.Sprintf("DirectoryEntry<NAME=[%s] INODE=(%d) TYPE=[%s]-(%d)>", de.Name(), de.data.Inode, de.TypeName(), de.data.FileType)
}
