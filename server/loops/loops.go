package loops

import (
	"errors"
	"sync"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

var Scheme = schemes.ByName("Ed25519-Dilithium2")

type AllHeatMaps struct {
	Nodes map[[32]byte]*LoopStats
}

type SphinxLoopStats struct {
	MixIdentityHash *[32]byte
	Payload         []byte
	Signature       []byte
}

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
	return &Cache{
		mapping: new(sync.Map),
	}
}

func (c *Cache) Retrieve(epoch uint64) []byte {
	epochMap, ok := c.mapping.Load(epoch)
	if !ok {
		blob, err := cbor.Marshal(&AllHeatMaps{})
		if err != nil {
			panic(err)
		}
		return blob
	}
	m := &AllHeatMaps{
		Nodes: make(map[[32]byte]*LoopStats),
	}
	epochMap.(*sync.Map).Range(func(key, value any) bool {
		mixid := key.(*[32]byte)
		stats := value.(*LoopStats)
		m.Nodes[*mixid] = stats
		return true
	})
	blob, err := cbor.Marshal(m)
	if err != nil {
		panic(err)
	}
	return blob
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
