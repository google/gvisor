// Copyright 2024 The gVisor Authors.
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

//go:build !network_plugins
// +build !network_plugins

package cgo

import (
	"syscall"
	"unsafe"
)

// GetPtr is a non-cgo stub function.
func GetPtr(bs []byte) unsafe.Pointer {
	panic("unimplemented")
}

// EpollCreate is a non-cgo stub function.
func EpollCreate() int {
	panic("unimplemented")
}

// EpollCtl is a non-cgo stub function.
func EpollCtl(epfd int32, op int, handle, events uint32) {
	panic("unimplemented")
}

// EpollWait is a non-cgo stub function.
func EpollWait(epfd int32, events []syscall.EpollEvent, n int, us int) int {
	panic("unimplemented")
}

// Socket is a non-cgo stub function.
func Socket(domain, skType, protocol int) int64 {
	panic("unimplemented")
}

// Bind is a non-cgo stub function.
func Bind(handle uint32, sa []byte) int64 {
	panic("unimplemented")
}

// Listen is a non-cgo stub function.
func Listen(handle uint32, backlog int) int64 {
	panic("unimplemented")
}

// Accept is a non-cgo stub function.
func Accept(handle uint32, addrPtr *byte, lenPtr *uint32) int64 {
	panic("unimplemented")
}

// Ioctl is a non-cgo stub function.
func Ioctl(handle uint32, cmd uint32, buf []byte) int64 {
	panic("unimplemented")
}

// Connect is a non-cgo stub function.
func Connect(handle uint32, addr []byte) int64 {
	panic("unimplemented")
}

// Getsockopt is a non-cgo stub function.
func Getsockopt(handle uint32, l int, n int, val []byte, s int) (int64, int) {
	panic("unimplemented")
}

// Setsockopt is a non-cgo stub function.
func Setsockopt(handle uint32, l int, n int, val []byte) int64 {
	panic("unimplemented")
}

// Shutdown is a non-cgo stub function.
func Shutdown(handle uint32, how int) int64 {
	panic("unimplemented")
}

// Close is a non-cgo stub function.
func Close(handle uint32) {
	panic("unimplemented")
}

// Getsockname is a non-cgo stub function.
func Getsockname(handle uint32, addr []byte, addrlen *uint32) int64 {
	panic("unimplemented")
}

// GetPeername is a non-cgo stub function.
func GetPeername(handle uint32, addr []byte, addrlen *uint32) int64 {
	panic("unimplemented")
}

// Readiness is a non-cgo stub function.
func Readiness(handle uint32, mask uint64) int64 {
	panic("unimplemented")
}

// Read is a non-cgo stub function.
func Read(handle uint32, buf uintptr, count int) int64 {
	panic("unimplemented")
}

// Readv is a non-cgo stub function.
func Readv(handle uint32, iovs []syscall.Iovec) int64 {
	panic("unimplemented")
}

// Recvfrom is a non-cgo stub function.
func Recvfrom(handle uint32, buf, addr []byte, flags int) (int64, int) {
	panic("unimplemented")
}

// Recvmsg is a non-cgo stub function.
func Recvmsg(handle uint32, iovs []syscall.Iovec, addr, control []byte, flags int) (int64, int, int, int) {
	panic("unimplemented")
}

// Write is a non-cgo stub function.
func Write(handle uint32, buf uintptr, count int) int64 {
	panic("unimplemented")
}

// Writev is a non-cgo stub function.
func Writev(handle uint32, iovs []syscall.Iovec) int64 {
	panic("unimplemented")
}

// Sendto is a non-cgo stub function.
func Sendto(handle uint32, buf uintptr, count int, flags int, addr []byte) int64 {
	panic("unimplemented")
}

// Sendmsg is a non-cgo stub function.
func Sendmsg(handle uint32, iovs []syscall.Iovec, addr []byte, flags int) int64 {
	panic("unimplemented")
}

// InitStack is a non-cgo stub function.
func InitStack(initStr string, fds []int) error {
	panic("unimplemented")
}

// PreInitStack is a non-cgo stub function.
func PreInitStack(pid int) (string, []int, error) {
	panic("unimplemented")
}
