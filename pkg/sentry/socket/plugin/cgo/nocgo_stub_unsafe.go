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

// Package cgo provides interfaces definition to interact with third-party
// network stack. It also implements CGO wrappers to handle Golang arguments
// to CGO and CGO return values to Golang.
//
// Third-party external network stack will implement interfaces defined in this
// package in order to be used by gVisor.
package cgo

import (
	"syscall"
	"unsafe"
)

func GetPtr(bs []byte) unsafe.Pointer {
	panic("unimplemented")
}
func EpollCreate() int {
	panic("unimplemented")
}
func EpollCtl(epfd int32, op int, handle, events uint32) {
	panic("unimplemented")
}

func EpollWait(epfd int32, events []syscall.EpollEvent, n int, us int) int {
	panic("unimplemented")
}
func Socket(domain, skType, protocol int) int64 {
	panic("unimplemented")
}
func Bind(handle uint32, sa []byte) int64 {
	panic("unimplemented")
}
func Listen(handle uint32, backlog int) int64 {
	panic("unimplemented")
}
func Accept(handle uint32, addrPtr *byte, lenPtr *uint32) int64 {
	panic("unimplemented")
}
func Ioctl(handle uint32, cmd uint32, buf []byte) int64 {
	panic("unimplemented")
}
func Connect(handle uint32, addr []byte) int64 {
	panic("unimplemented")
}
func Getsockopt(handle uint32, l int, n int, val []byte, s int) (int64, int) {
	panic("unimplemented")
}
func Setsockopt(handle uint32, l int, n int, val []byte) int64 {
	panic("unimplemented")
}
func Shutdown(handle uint32, how int) int64 {
	panic("unimplemented")
}
func Close(handle uint32) {
	panic("unimplemented")
}
func Getsockname(handle uint32, addr []byte, addrlen *uint32) int64 {
	panic("unimplemented")
}
func GetPeername(handle uint32, addr []byte, addrlen *uint32) int64 {
	panic("unimplemented")
}
func Readiness(handle uint32, mask uint64) int64 {
	panic("unimplemented")
}
func Read(handle uint32, buf uintptr, count int) int64 {
	panic("unimplemented")
}
func Readv(handle uint32, iovs []syscall.Iovec) int64 {
	panic("unimplemented")
}
func Recvfrom(handle uint32, buf, addr []byte, flags int) (int64, int) {
	panic("unimplemented")
}
func Recvmsg(handle uint32, iovs []syscall.Iovec, addr, control []byte, flags int) (int64, int, int, int) {
	panic("unimplemented")
}
func Write(handle uint32, buf uintptr, count int) int64 {
	panic("unimplemented")
}
func Writev(handle uint32, iovs []syscall.Iovec) int64 {
	panic("unimplemented")
}
func Sendto(handle uint32, buf uintptr, count int, flags int, addr []byte) int64 {
	panic("unimplemented")
}
func Sendmsg(handle uint32, iovs []syscall.Iovec, addr []byte, flags int) int64 {
	panic("unimplemented")
}
func InitStack(initStr string, fds []int) error {
	panic("unimplemented")
}
func PreInitStack(pid int) (string, []int, error) {
	panic("unimplemented")
}
