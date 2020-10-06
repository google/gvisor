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

package linux

const (
	// IFNAMSIZ is the size of the name field for IFReq.
	IFNAMSIZ = 16
)

// IFReq is an interface request.
//
// +marshal
type IFReq struct {
	// IFName is an encoded name, normally null-terminated. This should be
	// accessed via the Name and SetName functions.
	IFName [IFNAMSIZ]byte

	// Data is the union of the following structures:
	//
	//	struct sockaddr ifr_addr;
	//	struct sockaddr ifr_dstaddr;
	//	struct sockaddr ifr_broadaddr;
	//	struct sockaddr ifr_netmask;
	//	struct sockaddr ifr_hwaddr;
	//	short           ifr_flags;
	//	int             ifr_ifindex;
	//	int             ifr_metric;
	//	int             ifr_mtu;
	//	struct ifmap    ifr_map;
	//	char            ifr_slave[IFNAMSIZ];
	//	char            ifr_newname[IFNAMSIZ];
	//	char           *ifr_data;
	Data [24]byte
}

// Name returns the name.
func (ifr *IFReq) Name() string {
	for c := 0; c < len(ifr.IFName); c++ {
		if ifr.IFName[c] == 0 {
			return string(ifr.IFName[:c])
		}
	}
	return string(ifr.IFName[:])
}

// SetName sets the name.
func (ifr *IFReq) SetName(name string) {
	n := copy(ifr.IFName[:], []byte(name))
	for i := n; i < len(ifr.IFName); i++ {
		ifr.IFName[i] = 0
	}
}

// SizeOfIFReq is the binary size of an IFReq struct (40 bytes).
var SizeOfIFReq = (*IFReq)(nil).SizeBytes()

// IFMap contains interface hardware parameters.
type IFMap struct {
	MemStart uint64
	MemEnd   uint64
	BaseAddr int16
	IRQ      byte
	DMA      byte
	Port     byte
	_        [3]byte // Pad to sizeof(struct ifmap).
}

// IFConf is used to return a list of interfaces and their addresses. See
// netdevice(7) and struct ifconf for more detail on its use.
//
// +marshal
type IFConf struct {
	Len int32
	_   [4]byte // Pad to sizeof(struct ifconf).
	Ptr uint64
}
