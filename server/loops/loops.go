package loops

import (
	"errors"
	"sync"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

type LoopStats struct {
	Epoch           uint64
	MixIdentityHash *[32]byte
	Ratios          map[[32]byte]float64
}

// Cache scheme under `mapping` field is as follows:
//
// mapping Epoch ID -> to another sync.Map with mapping
//
//	Mix ID Hash -> LoopStats
type Cache struct {
	mapping *sync.Map
}

func New() *Cache {
	c := &Cache{}
	return c
}

// XXX FIXME(David): add garbage collection
func (c *Cache) Store(stats *LoopStats) error {
	epoch, _, _ := epochtime.Now()
	if stats.Epoch != (epoch - 1) {
		return errors.New("failed to Store: LoopStats must be for previous epoch.")
	}
	actual, _ := c.mapping.LoadOrStore(stats.Epoch, new(sync.Map))
	innerMap, ok := actual.(*sync.Map)
	if !ok {
		panic("inner map should always be a sync.Map instance")
	}
	_, _ = innerMap.LoadOrStore(stats.MixIdentityHash, stats)
	return nil
}
