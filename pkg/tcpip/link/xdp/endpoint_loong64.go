//go:build linux && loong64
// +build linux,loong64

// LoongArch stub: AF_XDP is not implemented. Field names match the
// amd64/arm64 Options struct so runsc/boot/network.go can construct an
// &xdp.Options literal — the values are ignored because New always
// returns an error.

package xdp

import (
	"errors"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Options struct {
	FD                int
	Address           tcpip.LinkAddress
	TXChecksumOffload bool
	RXChecksumOffload bool
	InterfaceIndex    int
	Bind              bool
	GRO               bool
}

func New(opts *Options) (stack.LinkEndpoint, error) {
	return nil, errors.New("AF_XDP is not implemented on LoongArch64")
}
