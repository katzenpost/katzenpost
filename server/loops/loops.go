package loops

import (
	"errors"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/sphinx"
)

type LoopStats struct {
	Epoch           uint64
	MixIdentityHash *[32]byte
	Stats           []*LoopStat
}

type LoopStat struct {
	ForwardPath []*sphinx.PathHop
	ReplyPath   []*sphinx.PathHop
	SentTime    time.Time
	IsSuccess   bool
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
