// automatically generated by stateify.

package vfio

import (
	"context"

	"gvisor.dev/gvisor/pkg/state"
)

func (r *DevAddrRange) StateTypeName() string {
	return "pkg/sentry/devices/tpuproxy/vfio.DevAddrRange"
}

func (r *DevAddrRange) StateFields() []string {
	return []string{
		"Start",
		"End",
	}
}

func (r *DevAddrRange) beforeSave() {}

// +checklocksignore
func (r *DevAddrRange) StateSave(stateSinkObject state.Sink) {
	r.beforeSave()
	stateSinkObject.Save(0, &r.Start)
	stateSinkObject.Save(1, &r.End)
}

func (r *DevAddrRange) afterLoad(context.Context) {}

// +checklocksignore
func (r *DevAddrRange) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &r.Start)
	stateSourceObject.Load(1, &r.End)
}

func (s *DevAddrSet) StateTypeName() string {
	return "pkg/sentry/devices/tpuproxy/vfio.DevAddrSet"
}

func (s *DevAddrSet) StateFields() []string {
	return []string{
		"root",
	}
}

func (s *DevAddrSet) beforeSave() {}

// +checklocksignore
func (s *DevAddrSet) StateSave(stateSinkObject state.Sink) {
	s.beforeSave()
	var rootValue []DevAddrFlatSegment
	rootValue = s.saveRoot()
	stateSinkObject.SaveValue(0, rootValue)
}

func (s *DevAddrSet) afterLoad(context.Context) {}

// +checklocksignore
func (s *DevAddrSet) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.LoadValue(0, new([]DevAddrFlatSegment), func(y any) { s.loadRoot(ctx, y.([]DevAddrFlatSegment)) })
}

func (n *DevAddrnode) StateTypeName() string {
	return "pkg/sentry/devices/tpuproxy/vfio.DevAddrnode"
}

func (n *DevAddrnode) StateFields() []string {
	return []string{
		"nrSegments",
		"parent",
		"parentIndex",
		"hasChildren",
		"maxGap",
		"keys",
		"values",
		"children",
	}
}

func (n *DevAddrnode) beforeSave() {}

// +checklocksignore
func (n *DevAddrnode) StateSave(stateSinkObject state.Sink) {
	n.beforeSave()
	stateSinkObject.Save(0, &n.nrSegments)
	stateSinkObject.Save(1, &n.parent)
	stateSinkObject.Save(2, &n.parentIndex)
	stateSinkObject.Save(3, &n.hasChildren)
	stateSinkObject.Save(4, &n.maxGap)
	stateSinkObject.Save(5, &n.keys)
	stateSinkObject.Save(6, &n.values)
	stateSinkObject.Save(7, &n.children)
}

func (n *DevAddrnode) afterLoad(context.Context) {}

// +checklocksignore
func (n *DevAddrnode) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &n.nrSegments)
	stateSourceObject.Load(1, &n.parent)
	stateSourceObject.Load(2, &n.parentIndex)
	stateSourceObject.Load(3, &n.hasChildren)
	stateSourceObject.Load(4, &n.maxGap)
	stateSourceObject.Load(5, &n.keys)
	stateSourceObject.Load(6, &n.values)
	stateSourceObject.Load(7, &n.children)
}

func (d *DevAddrFlatSegment) StateTypeName() string {
	return "pkg/sentry/devices/tpuproxy/vfio.DevAddrFlatSegment"
}

func (d *DevAddrFlatSegment) StateFields() []string {
	return []string{
		"Start",
		"End",
		"Value",
	}
}

func (d *DevAddrFlatSegment) beforeSave() {}

// +checklocksignore
func (d *DevAddrFlatSegment) StateSave(stateSinkObject state.Sink) {
	d.beforeSave()
	stateSinkObject.Save(0, &d.Start)
	stateSinkObject.Save(1, &d.End)
	stateSinkObject.Save(2, &d.Value)
}

func (d *DevAddrFlatSegment) afterLoad(context.Context) {}

// +checklocksignore
func (d *DevAddrFlatSegment) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &d.Start)
	stateSourceObject.Load(1, &d.End)
	stateSourceObject.Load(2, &d.Value)
}

func (dev *tpuDevice) StateTypeName() string {
	return "pkg/sentry/devices/tpuproxy/vfio.tpuDevice"
}

func (dev *tpuDevice) StateFields() []string {
	return []string{
		"mu",
		"minor",
		"num",
		"useDevGofer",
	}
}

func (dev *tpuDevice) beforeSave() {}

// +checklocksignore
func (dev *tpuDevice) StateSave(stateSinkObject state.Sink) {
	dev.beforeSave()
	stateSinkObject.Save(0, &dev.mu)
	stateSinkObject.Save(1, &dev.minor)
	stateSinkObject.Save(2, &dev.num)
	stateSinkObject.Save(3, &dev.useDevGofer)
}

func (dev *tpuDevice) afterLoad(context.Context) {}

// +checklocksignore
func (dev *tpuDevice) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &dev.mu)
	stateSourceObject.Load(1, &dev.minor)
	stateSourceObject.Load(2, &dev.num)
	stateSourceObject.Load(3, &dev.useDevGofer)
}

func init() {
	state.Register((*DevAddrRange)(nil))
	state.Register((*DevAddrSet)(nil))
	state.Register((*DevAddrnode)(nil))
	state.Register((*DevAddrFlatSegment)(nil))
	state.Register((*tpuDevice)(nil))
}