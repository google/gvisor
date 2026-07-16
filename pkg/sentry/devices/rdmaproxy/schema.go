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

package rdmaproxy

import (
	"sync"

	"gvisor.dev/gvisor/pkg/abi/ib"
)

// This file defines the explicit, allowlisting schema that drives translation
// of RDMA_VERBS_IOCTL requests. Every (object, method) pair the proxy accepts
// is described here, and every attribute within it carries a declared type.
//
// The declared type — NOT any runtime probing of the guest's memory — decides
// whether an attribute's data field is an inline value, a user pointer to copy
// in, an output buffer to allocate, an object handle to pass through, or a file
// descriptor to translate. This is the security-critical difference from a
// probe-by-CopyIn design: a guest cannot coerce the proxy into treating an
// output pointer as input (arbitrary write) or an inline value as a pointer
// (arbitrary read) by lying about its memory, because the direction is fixed by
// the kernel ABI, which is additive-only and stable since Linux 4.20.
//
// Object/method/attribute IDs are defined in pkg/abi/ib; the schemas below
// are verified against the method definitions in
// drivers/infiniband/core/uverbs_std_types*.c.

// AttrType classifies how the proxy must translate an attribute's data field
// before forwarding the ioctl to the host and after it returns.
type AttrType uint8

const (
	// AttrPtrIn is an input value. If len<=8 the data field holds the value
	// inline and is forwarded untouched; if len>8 the data field is a guest
	// pointer whose contents are copied into a sentry buffer and the field is
	// rewritten to the sentry address.
	AttrPtrIn AttrType = iota
	// AttrPtrOut is an output buffer. The data field is ALWAYS a guest
	// pointer (even for 4-byte outputs); the proxy allocates a sentry buffer,
	// rewrites the field, and copies the buffer back to the guest pointer
	// after the call.
	AttrPtrOut
	// AttrInline is an inline scalar (value in the data field) that a
	// method-specific handler reads by value. The generic loop leaves it in
	// place but rejects a guest-supplied pointer (len>8), which the handler
	// would otherwise misread as the value.
	AttrInline
	// AttrIdr is an object handle (len==0, data=handle). It is passed through
	// unchanged: with a single host uverbs context per FD the guest and host
	// share one handle namespace. For UVERBS_ACCESS_NEW attrs the kernel
	// writes the freshly allocated handle into the data field of the
	// forwarded buffer, which reaches the guest via copy-out.
	AttrIdr
	// AttrFdIn is an input file descriptor (len==0, data=fd) referencing an
	// object the proxy previously wrapped (an async-event FD). The guest fd
	// number is translated to the host fd before the call and restored after.
	AttrFdIn
	// AttrFdNew is an output file descriptor (len==0). The kernel installs a
	// host fd in the sentry process and writes its number into the data
	// field; the proxy wraps it in a sentry FD and rewrites the field.
	AttrFdNew
	// AttrRawFd is a raw file descriptor (len==0, data_s64=fd), translated
	// like AttrFdIn when non-negative.
	AttrRawFd
	// AttrUnsupported is a modeled-but-rejected attribute (e.g. UMEM or a
	// buffer-FD path the proxy does not implement). Its presence in a request
	// fails the ioctl with EINVAL rather than being silently forwarded.
	AttrUnsupported
)

// DmaKind selects the method-level DMA-mirroring / resource-tracking behavior
// applied in addition to the generic per-attribute translation.
type DmaKind uint8

const (
	DmaNone DmaKind = iota
	// DmaMRReg mirrors the guest pages referenced by the REG_MR ADDR/LENGTH
	// attributes and tracks the resulting MR handle for teardown.
	DmaMRReg
	// DmaMRRegDMABuf tracks the DMABUF MR handle (no page mirroring; the DMA
	// buffer is resolved through the dma-buf framework, not guest VMAs).
	DmaMRRegDMABuf
	// DmaMRDestroy releases the pages mirrored for the MR being destroyed.
	DmaMRDestroy
	// DmaCQCreate / DmaQPCreate mirror the vendor DMA buffers via the driver
	// plug-in and track the CQ/QP handle.
	DmaCQCreate
	DmaQPCreate
	// DmaCQDestroy / DmaQPDestroy release the mirrors tracked at create.
	DmaCQDestroy
	DmaQPDestroy
	// DmaAsyncAlloc wraps the newly allocated async-event host fd.
	DmaAsyncAlloc
	// DmaInvokeWrite handles the legacy write ABI wrapped in INVOKE_WRITE: it
	// forwards CORE_IN/CORE_OUT opaquely, and for the write-path REG_MR/DEREG_MR
	// commands mirrors the guest MR pages and tracks the MR handle.
	DmaInvokeWrite
)

// MethodSchema is the complete, verified description of one (object, method).
type MethodSchema struct {
	Dma DmaKind
	// HandleAttr is the attribute carrying this object's IDR handle, used for
	// create/destroy resource tracking. Only meaningful when Dma tracks a
	// handle.
	HandleAttr uint16
	// Attrs maps attribute id -> type. Any attribute not present here causes
	// the request to be rejected.
	Attrs map[uint16]AttrType
}

// schemas is the allowlist of supported (object, method) pairs, keyed by
// (object<<16 | method). Requests outside this set are rejected with EINVAL.
// Built on first use so that a runsc without RDMA never allocates it.
var (
	schemasOnce sync.Once
	schemas     map[uint32]*MethodSchema
)

func SchemaKey(object, method uint16) uint32 {
	return uint32(object)<<16 | uint32(method)
}

func lookupSchema(object, method uint16) *MethodSchema {
	schemasOnce.Do(func() { schemas = buildSchemas() })
	return schemas[SchemaKey(object, method)]
}

func buildSchemas() map[uint32]*MethodSchema {
	m := map[uint32]*MethodSchema{
		SchemaKey(ib.UVERBS_OBJECT_DEVICE, ib.UVERBS_METHOD_INVOKE_WRITE): {
			// The compatibility wrapper for the legacy write ABI. CORE_IN /
			// CORE_OUT are opaque command/response blobs (the kernel validates
			// their contents); the DMA-relevant write commands are handled by
			// DmaInvokeWrite. This one entry covers alloc_pd, dealloc_pd,
			// modify_qp, query_qp, query_device, create_ah, etc.
			Dma: DmaInvokeWrite,
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_CORE_IN:   AttrPtrIn,
				ib.UVERBS_ATTR_CORE_OUT:  AttrPtrOut,
				ib.UVERBS_ATTR_WRITE_CMD: AttrInline,
				ib.UVERBS_ATTR_UHW_IN:    AttrPtrIn,
				ib.UVERBS_ATTR_UHW_OUT:   AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_DEVICE, ib.UVERBS_METHOD_GET_CONTEXT): {
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_GET_CONTEXT_NUM_COMP_VECTORS: AttrPtrOut,
				ib.UVERBS_ATTR_GET_CONTEXT_CORE_SUPPORT:     AttrPtrOut,
				// FD_ARR passes an array of fds that would need per-element
				// app->host translation; unused by mlx5 get_context, so
				// reject rather than forward untranslated fds.
				ib.UVERBS_ATTR_GET_CONTEXT_FD_ARR: AttrUnsupported,
				ib.UVERBS_ATTR_UHW_IN:             AttrPtrIn,
				ib.UVERBS_ATTR_UHW_OUT:            AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_DEVICE, ib.UVERBS_METHOD_QUERY_CONTEXT): {
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_QUERY_CONTEXT_NUM_COMP_VECTORS: AttrPtrOut,
				ib.UVERBS_ATTR_QUERY_CONTEXT_CORE_SUPPORT:     AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_DEVICE, ib.UVERBS_METHOD_QUERY_PORT): {
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_QUERY_PORT_PORT_NUM: AttrPtrIn,
				ib.UVERBS_ATTR_QUERY_PORT_RESP:     AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_DEVICE, ib.UVERBS_METHOD_QUERY_GID_TABLE): {
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_QUERY_GID_TABLE_ENTRY_SIZE:       AttrPtrIn,
				ib.UVERBS_ATTR_QUERY_GID_TABLE_FLAGS:            AttrPtrIn,
				ib.UVERBS_ATTR_QUERY_GID_TABLE_RESP_ENTRIES:     AttrPtrOut,
				ib.UVERBS_ATTR_QUERY_GID_TABLE_RESP_NUM_ENTRIES: AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_DEVICE, ib.UVERBS_METHOD_QUERY_GID_ENTRY): {
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_QUERY_GID_ENTRY_PORT:       AttrPtrIn,
				ib.UVERBS_ATTR_QUERY_GID_ENTRY_GID_INDEX:  AttrPtrIn,
				ib.UVERBS_ATTR_QUERY_GID_ENTRY_FLAGS:      AttrPtrIn,
				ib.UVERBS_ATTR_QUERY_GID_ENTRY_RESP_ENTRY: AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_PD, ib.UVERBS_METHOD_PD_DESTROY): {
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_DESTROY_PD_HANDLE: AttrIdr,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_MR, ib.UVERBS_METHOD_REG_MR): {
			Dma: DmaMRReg, HandleAttr: ib.UVERBS_ATTR_REG_MR_HANDLE,
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_REG_MR_HANDLE:       AttrIdr,
				ib.UVERBS_ATTR_REG_MR_PD_HANDLE:    AttrIdr,
				ib.UVERBS_ATTR_REG_MR_DMA_HANDLE:   AttrIdr,
				ib.UVERBS_ATTR_REG_MR_IOVA:         AttrPtrIn,
				ib.UVERBS_ATTR_REG_MR_ADDR:         AttrInline,
				ib.UVERBS_ATTR_REG_MR_LENGTH:       AttrInline,
				ib.UVERBS_ATTR_REG_MR_ACCESS_FLAGS: AttrPtrIn,
				ib.UVERBS_ATTR_REG_MR_FD:           AttrRawFd,
				ib.UVERBS_ATTR_REG_MR_FD_OFFSET:    AttrPtrIn,
				ib.UVERBS_ATTR_REG_MR_RESP_LKEY:    AttrPtrOut,
				ib.UVERBS_ATTR_REG_MR_RESP_RKEY:    AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_MR, ib.UVERBS_METHOD_REG_DMABUF_MR): {
			Dma: DmaMRRegDMABuf, HandleAttr: ib.UVERBS_ATTR_REG_DMABUF_MR_HANDLE,
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_REG_DMABUF_MR_HANDLE:    AttrIdr,
				ib.UVERBS_ATTR_REG_DMABUF_MR_PD_HANDLE: AttrIdr,
				ib.UVERBS_ATTR_REG_DMABUF_MR_OFFSET:    AttrPtrIn,
				ib.UVERBS_ATTR_REG_DMABUF_MR_LENGTH:    AttrPtrIn,
				ib.UVERBS_ATTR_REG_DMABUF_MR_IOVA:      AttrPtrIn,
				// The DMABUF fd is translated from an app fd to a host fd in
				// the DMABUF-specific pre-processing step.
				ib.UVERBS_ATTR_REG_DMABUF_MR_FD:           AttrInline,
				ib.UVERBS_ATTR_REG_DMABUF_MR_ACCESS_FLAGS: AttrPtrIn,
				ib.UVERBS_ATTR_REG_DMABUF_MR_RESP_LKEY:    AttrPtrOut,
				ib.UVERBS_ATTR_REG_DMABUF_MR_RESP_RKEY:    AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_MR, ib.UVERBS_METHOD_MR_DESTROY): {
			Dma: DmaMRDestroy, HandleAttr: ib.UVERBS_ATTR_DESTROY_MR_HANDLE,
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_DESTROY_MR_HANDLE: AttrIdr,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_CQ, ib.UVERBS_METHOD_CQ_CREATE): {
			Dma: DmaCQCreate, HandleAttr: ib.UVERBS_ATTR_CREATE_CQ_HANDLE,
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_CREATE_CQ_HANDLE:       AttrIdr,
				ib.UVERBS_ATTR_CREATE_CQ_CQE:          AttrPtrIn,
				ib.UVERBS_ATTR_CREATE_CQ_USER_HANDLE:  AttrPtrIn,
				ib.UVERBS_ATTR_CREATE_CQ_COMP_CHANNEL: AttrFdIn,
				ib.UVERBS_ATTR_CREATE_CQ_COMP_VECTOR:  AttrPtrIn,
				ib.UVERBS_ATTR_CREATE_CQ_FLAGS:        AttrPtrIn,
				ib.UVERBS_ATTR_CREATE_CQ_RESP_CQE:     AttrPtrOut,
				ib.UVERBS_ATTR_CREATE_CQ_EVENT_FD:     AttrFdIn,
				// The BUFFER_* / UMEM registration path is an alternative
				// to the vendor UHW DMA buffers; mlx5 uses UHW, so these
				// are rejected rather than half-supported.
				ib.UVERBS_ATTR_CREATE_CQ_BUFFER_VA:     AttrUnsupported,
				ib.UVERBS_ATTR_CREATE_CQ_BUFFER_LENGTH: AttrUnsupported,
				ib.UVERBS_ATTR_CREATE_CQ_BUFFER_FD:     AttrUnsupported,
				ib.UVERBS_ATTR_CREATE_CQ_BUFFER_OFFSET: AttrUnsupported,
				ib.UVERBS_ATTR_CREATE_CQ_BUF_UMEM:      AttrUnsupported,
				ib.UVERBS_ATTR_UHW_IN:                  AttrPtrIn,
				ib.UVERBS_ATTR_UHW_OUT:                 AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_CQ, ib.UVERBS_METHOD_CQ_DESTROY): {
			Dma: DmaCQDestroy, HandleAttr: ib.UVERBS_ATTR_DESTROY_CQ_HANDLE,
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_DESTROY_CQ_HANDLE: AttrIdr,
				ib.UVERBS_ATTR_DESTROY_CQ_RESP:   AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_QP, ib.UVERBS_METHOD_QP_CREATE): {
			Dma: DmaQPCreate, HandleAttr: ib.UVERBS_ATTR_CREATE_QP_HANDLE,
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_CREATE_QP_HANDLE:           AttrIdr,
				ib.UVERBS_ATTR_CREATE_QP_XRCD_HANDLE:      AttrIdr,
				ib.UVERBS_ATTR_CREATE_QP_PD_HANDLE:        AttrIdr,
				ib.UVERBS_ATTR_CREATE_QP_SRQ_HANDLE:       AttrIdr,
				ib.UVERBS_ATTR_CREATE_QP_SEND_CQ_HANDLE:   AttrIdr,
				ib.UVERBS_ATTR_CREATE_QP_RECV_CQ_HANDLE:   AttrIdr,
				ib.UVERBS_ATTR_CREATE_QP_IND_TABLE_HANDLE: AttrIdr,
				ib.UVERBS_ATTR_CREATE_QP_USER_HANDLE:      AttrPtrIn,
				ib.UVERBS_ATTR_CREATE_QP_CAP:              AttrPtrIn,
				ib.UVERBS_ATTR_CREATE_QP_TYPE:             AttrPtrIn,
				ib.UVERBS_ATTR_CREATE_QP_FLAGS:            AttrPtrIn,
				ib.UVERBS_ATTR_CREATE_QP_SOURCE_QPN:       AttrPtrIn,
				ib.UVERBS_ATTR_CREATE_QP_EVENT_FD:         AttrFdIn,
				ib.UVERBS_ATTR_CREATE_QP_RESP_CAP:         AttrPtrOut,
				ib.UVERBS_ATTR_CREATE_QP_RESP_QP_NUM:      AttrPtrOut,
				ib.UVERBS_ATTR_CREATE_QP_BUF_UMEM:         AttrUnsupported,
				ib.UVERBS_ATTR_CREATE_QP_RQ_BUF_UMEM:      AttrUnsupported,
				ib.UVERBS_ATTR_CREATE_QP_SQ_BUF_UMEM:      AttrUnsupported,
				ib.UVERBS_ATTR_UHW_IN:                     AttrPtrIn,
				ib.UVERBS_ATTR_UHW_OUT:                    AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_QP, ib.UVERBS_METHOD_QP_DESTROY): {
			Dma: DmaQPDestroy, HandleAttr: ib.UVERBS_ATTR_DESTROY_QP_HANDLE,
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_DESTROY_QP_HANDLE: AttrIdr,
				ib.UVERBS_ATTR_DESTROY_QP_RESP:   AttrPtrOut,
			},
		},
		SchemaKey(ib.UVERBS_OBJECT_ASYNC_EVENT, ib.UVERBS_METHOD_ASYNC_EVENT_ALLOC): {
			Dma: DmaAsyncAlloc, HandleAttr: ib.UVERBS_ATTR_ASYNC_EVENT_ALLOC_FD_HANDLE,
			Attrs: map[uint16]AttrType{
				ib.UVERBS_ATTR_ASYNC_EVENT_ALLOC_FD_HANDLE: AttrFdNew,
			},
		},
	}
	// Merge the driver-namespace (object, method) pairs each registered vendor
	// plug-in models (e.g. the mlx5 UAR); these carry no core DMA semantics.
	rangeDrivers(func(d Driver) {
		for k, s := range d.Schemas() {
			m[k] = s
		}
	})
	return m
}
