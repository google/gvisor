package fsutil

import (
        "sync"
        "sync/atomic"
        "time"
        "runtime"

        "gvisor.dev/gvisor/pkg/ilist"
        "gvisor.dev/gvisor/pkg/log"
        "gvisor.dev/gvisor/pkg/sentry/context"
        "gvisor.dev/gvisor/pkg/sentry/memmap"
        "gvisor.dev/gvisor/pkg/sentry/pgalloc"
        "gvisor.dev/gvisor/pkg/sentry/platform"
        "gvisor.dev/gvisor/pkg/sentry/usermem"
)

const (
        LRU_ACTIVE_LIST = 0
        LRU_INACTIVE_LIST = 1
        LRU_LIST_NUM = 2
)

type LruEntry struct {
	ilist.Entry
	fr platform.FileRange
	mr memmap.MappableRange
	c *CachingInodeOperations
	accessed bool
	lru int
}

type LruManager struct {
	destroyed bool
	forceReclaim bool

	// LRULists store the current file ranges consumed by all the files
        // with the minimum granularity of 4K
        // LRUMap records the mappings from the start of file range to its entry
        //
        // LRULists and LRUMap are protected by LRUMapMu
        lists [LRU_LIST_NUM]ilist.List
	length [LRU_LIST_NUM]int
        mappings map[uint64]*LruEntry
        lruMu sync.RWMutex

	f *pgalloc.MemoryFile
}

func NewLruEntry(fr platform.FileRange, mr memmap.MappableRange, c *CachingInodeOperations) *LruEntry {
        return &LruEntry{fr: fr, mr: mr, c: c, accessed: true, lru: LRU_ACTIVE_LIST}
}

func update(e *LruEntry, fr platform.FileRange, mr memmap.MappableRange, c *CachingInodeOperations) {
	e.fr = fr
	e.mr = mr
	e.c = c
	e.accessed = true
}

var mgrMu sync.Mutex
var mgrMap map[*pgalloc.MemoryFile]*LruManager = make(map[*pgalloc.MemoryFile]*LruManager)

func NewLruManager(interval time.Duration, f *pgalloc.MemoryFile) *LruManager {
	// Created only once for each MemoryFile
	if manager, ok := mgrMap[f]; ok {
		return manager
	}

	mgrMu.Lock()
	lru := &LruManager {
		destroyed: false,
		forceReclaim: false,
		mappings: make(map[uint64]*LruEntry),
		f: f,
	}
	for i := 0; i < LRU_LIST_NUM; i++ {
		lru.lists[i].Reset()
		lru.length[i] = 0
	}

	go lru.run(interval)
	mgrMap[f] = lru
	mgrMu.Unlock()
	return lru
}

func (m *LruManager) shrinkActiveListLocked(maxHarvest int) (*ilist.List, int) {
	var out ilist.List
	reclaimed := 0
	for e := m.lists[LRU_ACTIVE_LIST].Front(); e != nil && m.length[LRU_ACTIVE_LIST] > m.length[LRU_INACTIVE_LIST] && reclaimed < maxHarvest; {
		next := e.Next()
		if !e.(*LruEntry).accessed {
			// Second chance
			m.lists[LRU_ACTIVE_LIST].Remove(e)
			m.length[LRU_ACTIVE_LIST]--
			out.PushBack(e)
			reclaimed++
		} else {
			e.(*LruEntry).accessed = false
		}
		e = next
	}

	return &out, reclaimed
}

func (m *LruManager) shrinkInactiveListLocked(maxHarvest int) (*ilist.List, int) {
	var out ilist.List
	reclaimed := 0
	for e := m.lists[LRU_INACTIVE_LIST].Front(); e != nil && reclaimed < maxHarvest; {
		next := e.Next()
		if e.(*LruEntry).accessed {
			e.(*LruEntry).accessed = false
			m.lists[LRU_INACTIVE_LIST].Remove(e)
			m.length[LRU_INACTIVE_LIST]--
			// Repush in the front as this might be an occasional access
			//m.lists[LRU_ACTIVE_LIST].PushFront(e)
			m.lists[LRU_ACTIVE_LIST].PushBack(e)
			m.length[LRU_ACTIVE_LIST]++
		} else {
			m.lists[LRU_INACTIVE_LIST].Remove(e)
			m.length[LRU_INACTIVE_LIST]--
			out.PushBack(e)
		}
		reclaimed++
		e = next
	}

	return &out, reclaimed
}

func (m *LruManager) Kick() {
	m.forceReclaim = true
}

func (m *LruManager) doReclaim(maxHarvest int) {
	m.lruMu.Lock()
	active, reclaimedActive := m.shrinkActiveListLocked(maxHarvest)
	inactive, _ := m.shrinkInactiveListLocked(maxHarvest)

	// reinsert items in active  to global inactive lru list
	m.lists[LRU_INACTIVE_LIST].PushBackList(active)
	m.length[LRU_INACTIVE_LIST] += reclaimedActive
	m.lruMu.Unlock()

	// free the harvested inactive elements
	var backup ilist.List
	for e := inactive.Front(); e != nil; e = e.Next() {
		le := e.(*LruEntry)
		c := le.c
		c.mapsMu.Lock()
		c.dataMu.Lock()
		// writeback data if this range is dirty
		err := SyncDirty(context.Background(), le.mr, &c.cache, &c.dirty, uint64(c.attr.Size), c.mfp.MemoryFile(), c.backingFile.WriteFromBlocksAt)
		if err == nil {
			c.cache.Drop(le.mr, c.mfp.MemoryFile())
			c.mfp.MemoryFile().AccountCacheDrop(le.mr.Length())
		} else {
			backup.PushBack(e)
		}
		c.dataMu.Unlock()
		c.mapsMu.Unlock()
	}

	if backup.Empty() {
		return
	}
	m.lruMu.Lock()
	for e := backup.Front(); e != nil; e = e.Next() {
		m.lists[LRU_INACTIVE_LIST].PushFront(e)
	}
	m.lruMu.Unlock()
}

func (m *LruManager) run(interval time.Duration) {
	ticker := time.NewTicker(interval)
	// TODO. aribitrarily chosen
	maxHarvest := 64
	for !m.destroyed {
		if m.forceReclaim || m.f.CheckMemoryPressure() {
			m.forceReclaim = false
			m.f.ResetMemoryPressure()
			m.doReclaim(maxHarvest << 1)
			// do as many rounds of reclaimation under memory pressure
			continue
		}

		select {
		case <- ticker.C:
			m.doReclaim(maxHarvest)
		default:
			runtime.Gosched()
		}
	}
}

func (m *LruManager) Access(fr platform.FileRange) {
	m.lruMu.RLock()
	if entry, ok := m.mappings[fr.Start &^ (usermem.PageSize - 1)]; ok {
		// TODO. should we use atomic instead?
		entry.accessed = true
	}
	m.lruMu.RUnlock()
}

func (m *LruManager) Insert(e *LruEntry) {
	lru := e.lru
	fr := e.fr
	mr := e.mr
	c := e.c

	// fast path for inclusive ranges
	m.lruMu.RLock()
	if entry, ok := m.mappings[fr.Start &^ (usermem.PageSize - 1)]; ok {
		update(entry, fr, e.mr, c)
		m.lruMu.RUnlock()
		return
	}
	m.lruMu.RUnlock()

	m.lruMu.Lock()
	if entry, ok := m.mappings[fr.Start &^ (usermem.PageSize - 1)]; ok {
		update(entry, fr, mr, c)
	} else {
		m.lists[lru].PushBack(e)
		m.mappings[fr.Start &^ (usermem.PageSize - 1)] = e
		m.length[lru]++
	}
	m.lruMu.Unlock()
}

func (m *LruManager) Remove(e *LruEntry) {
	lru := e.lru
	m.lruMu.Lock()
	m.lists[lru].Remove(e)
	m.length[lru]--
	m.lruMu.Unlock()
}

func (m *LruManager) Destroyed() bool {
	return m.destroyed
}

func (m *LruManager) Destroy() {
	m.lruMu.Lock()
	m.destroyed = true
	for i := 0; i < LRU_LIST_NUM; i++ {
		m.lists[i].Reset()
		m.length[i] = 0
	}
	m.mappings = make(map[uint64]*LruEntry)
	m.lruMu.Unlock()
}

// PeriodicFlusher periodically flushes the dirty file ranges of each inode into memfd
// in the host. But we only do call SyncDirty here, not including fsync
type PeriodicFlusher struct {
	inodeList ilist.List
	inodeMu sync.RWMutex

	forceWriteback bool
	runnable bool
}

var pdfInited = int32(0)
var globalPDF *PeriodicFlusher = nil

func NewPeriodicFlusher(interval time.Duration) *PeriodicFlusher {
	if pdfInited != 0 || !atomic.CompareAndSwapInt32(&pdfInited, 0, 1) {
		for globalPDF == nil {
			runtime.Gosched()
		}
		return globalPDF;
	}

	globalPDF = &PeriodicFlusher{
		forceWriteback: false,
		runnable: false,
	}
	globalPDF.inodeList.Reset()
	globalPDF.Start(interval)

	return globalPDF
}

func (pdf *PeriodicFlusher) Start(interval time.Duration) {
	pdf.inodeList.Reset()
	pdf.runnable = true
	go pdf.run(interval)
}

func (pdf *PeriodicFlusher) Stop() {
	pdf.runnable = false
}

func (pdf *PeriodicFlusher) Kick() {
	pdf.forceWriteback = true
}

func (pdf *PeriodicFlusher) Attach(c *CachingInodeOperations) {
	pdf.inodeMu.Lock()
	pdf.inodeList.PushBack(c)
	pdf.inodeMu.Unlock()
}

func (pdf *PeriodicFlusher) Detach(c *CachingInodeOperations) {
	pdf.inodeMu.Lock()
	pdf.inodeList.Remove(c)
	pdf.inodeMu.Unlock()
}

func (pdf *PeriodicFlusher) flushDirty() {
	pdf.inodeMu.RLock()
	for e := pdf.inodeList.Front(); e != nil; e = e.Next() {
		c := e.(*CachingInodeOperations)
		if !c.dirtyAttr.Size {
			continue
		}
		// CachingInodeOperations.WriteOut does not use inode param
		if err := c.WriteOut(context.Background(), nil); err != nil {
			log.Debugf("Writeback cache failed in pdf = %v", pdf)
		}
	}
	pdf.inodeMu.RUnlock()
}

func (pdf *PeriodicFlusher) run(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for pdf.runnable {
		if pdf.inodeList.Empty() {
			runtime.Gosched()
			continue
		}

		if pdf.forceWriteback {
			pdf.forceWriteback = false
			pdf.flushDirty()
			continue
		}

		select {
		case <- ticker.C:
			pdf.flushDirty()
		default:
			runtime.Gosched()
			continue
		}
	}
}
