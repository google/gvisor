// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tun contains methods to open TAP and TUN devices.
package tun

import (
	"syscall"
	"unsafe"
)

// Open opens the specified TUN device, sets it to non-blocking mode, and
// returns its file descriptor.
func Open(name string) (int, error) {
	return open(name, syscall.IFF_TUN|syscall.IFF_NO_PI)
}

// OpenTAP opens the specified TAP device, sets it to non-blocking mode, and
// returns its file descriptor.
func OpenTAP(name string) (int, error) {
	return open(name, syscall.IFF_TAP|syscall.IFF_NO_PI)
}

func open(name string, flags uint16) (int, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return -1, err
	}

	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	copy(ifr.name[:], name)
	ifr.flags = flags
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return -1, errno
	}

	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	return fd, nil
}
