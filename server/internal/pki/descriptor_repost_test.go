// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

type keyedMixKeys struct{ fakeMixKeys }

func (keyedMixKeys) Get(uint64) ([]byte, bool) { return []byte{1}, true }

type statsDecoy struct{ glue.Decoy }

func (statsDecoy) GetStats(uint64) *loops.LoopStats { return nil }

type publishGlue struct {
	rotationGlue
	cfg   *config.Config
	idPub sign.PublicKey
	idKey sign.PrivateKey
	link  kem.PrivateKey
}

func (g *publishGlue) Config() *config.Config            { return g.cfg }
func (g *publishGlue) IdentityKey() sign.PrivateKey      { return g.idKey }
func (g *publishGlue) IdentityPublicKey() sign.PublicKey { return g.idPub }
func (g *publishGlue) LinkKey() kem.PrivateKey           { return g.link }
func (g *publishGlue) Decoy() glue.Decoy                 { return statsDecoy{} }

type rejectOncePoster struct {
	sync.Mutex
	posts []uint64
}

func (f *rejectOncePoster) GetPKIDocumentForEpoch(context.Context, uint64) (*cpki.Document, []byte, error) {
	return nil, nil, cpki.ErrNoDocument
}

func (f *rejectOncePoster) Post(_ context.Context, epoch uint64, _ sign.PrivateKey, _ sign.PublicKey, _ *cpki.MixDescriptor, _ *loops.LoopStats) error {
	f.Lock()
	defer f.Unlock()
	f.posts = append(f.posts, epoch)
	if len(f.posts) == 1 {
		return cpki.ErrInvalidPostEpoch
	}
	return nil
}

func newPublishPKI(t *testing.T, impl cpki.MixNodeClient) *pki {
	idPub, idKey, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	_, link, err := kemSchemes.ByName("xwing").GenerateKeyPair()
	require.NoError(t, err)
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	g := &publishGlue{
		rotationGlue: rotationGlue{mk: &keyedMixKeys{}},
		cfg:          &config.Config{Server: &config.Server{Identifier: "mix1"}},
		idPub:        idPub,
		idKey:        idKey,
		link:         link,
	}
	addrs, err := makeDescAddrMap([]string{"tcp://127.0.0.1:4242"})
	require.NoError(t, err)
	return &pki{
		glue:          g,
		log:           backend.GetLogger("pki"),
		impl:          impl,
		descAddrMap:   addrs,
		docs:          make(map[uint64]*pkicache.Entry),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
		advertising:   true,
	}
}

func TestRejectedDescriptorIsPostedAgainInsideTheWindow(t *testing.T) {
	const now = 1000
	setEpochClock(t, now, time.Second)
	f := &rejectOncePoster{}
	p := newPublishPKI(t, f)

	require.ErrorIs(t, p.publishDescriptorIfNeeded(context.Background()), cpki.ErrInvalidPostEpoch)
	require.NoError(t, p.publishDescriptorIfNeeded(context.Background()))
	require.Equal(t, []uint64{now + 1, now + 1}, f.posts)
	require.NoError(t, p.publishDescriptorIfNeeded(context.Background()))
	require.Len(t, f.posts, 2)
}

func TestUpdateTimerRepostsInsideTheUploadWindow(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		if p != 2*time.Minute {
			return
		}
		const now = 1000
		setEpochClock(t, now, time.Second)
		f := newAuthFixture(t)
		ent, _ := f.entry(t, now, -1, 0)
		mp := newPublishPKI(t, &rejectOncePoster{})
		mp.docs[now] = ent

		timer := time.NewTimer(time.Hour)
		defer timer.Stop()
		mp.updateTimer(timer)
		select {
		case <-timer.C:
		case <-time.After(epochtime.Period()/96 + 2*time.Second):
			require.FailNow(t, "mix slept past the upload window without its descriptor posted")
		}
	})
}
