// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"context"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/connlimit"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/mixkey"
)

type fakeMixKeys struct {
	generated []uint64
	prunes    int
	genErr    error
	didGen    bool
	didPrune  bool
}

func (f *fakeMixKeys) Halt() {}
func (f *fakeMixKeys) Generate(e uint64) (bool, error) {
	f.generated = append(f.generated, e)
	return f.didGen, f.genErr
}
func (f *fakeMixKeys) Prune() bool                      { f.prunes++; return f.didPrune }
func (f *fakeMixKeys) Get(uint64) ([]byte, bool)        { return nil, false }
func (f *fakeMixKeys) Shadow(map[uint64]*mixkey.MixKey) {}

type rotationGlue struct {
	mk        glue.MixKeys
	reshadows int
}

func (g *rotationGlue) Config() *config.Config            { return nil }
func (g *rotationGlue) LogBackend() *log.Backend          { return nil }
func (g *rotationGlue) IdentityKey() sign.PrivateKey      { return nil }
func (g *rotationGlue) IdentityPublicKey() sign.PublicKey { return nil }
func (g *rotationGlue) LinkKey() kem.PrivateKey           { return nil }
func (g *rotationGlue) Management() *thwack.Server        { return nil }
func (g *rotationGlue) MixKeys() glue.MixKeys             { return g.mk }
func (g *rotationGlue) PKI() glue.PKI                     { return nil }
func (g *rotationGlue) Gateway() glue.Gateway             { return nil }
func (g *rotationGlue) ServiceNode() glue.ServiceNode     { return nil }
func (g *rotationGlue) Scheduler() glue.Scheduler         { return nil }
func (g *rotationGlue) Connector() glue.Connector         { return nil }
func (g *rotationGlue) Listeners() []glue.Listener        { return nil }
func (g *rotationGlue) Decoy() glue.Decoy                 { return nil }
func (g *rotationGlue) PeerConnSet() *connlimit.PeerSet   { return nil }
func (g *rotationGlue) ReshadowCryptoWorkers()            { g.reshadows++ }

func newRotationPKI(t *testing.T, mk glue.MixKeys) (*pki, *rotationGlue) {
	t.Helper()
	backend, err := log.New("", "debug", false)
	require.NoError(t, err)
	g := &rotationGlue{mk: mk}
	return &pki{glue: g, log: backend.GetLogger("pki")}, g
}

func TestRotationPrunesEvenWhenNothingIsGenerated(t *testing.T) {
	mk := &fakeMixKeys{didGen: false, didPrune: true}
	p, g := newRotationPKI(t, mk)

	require.NoError(t, p.rotateMixKeys(42))
	require.Equal(t, []uint64{42}, mk.generated)
	require.Equal(t, 1, mk.prunes, "a rotation pass must prune")
	require.Equal(t, 1, g.reshadows, "dropping a key must reshadow the crypto workers")
}

func TestRotationReshadowsOnGenerationAlone(t *testing.T) {
	mk := &fakeMixKeys{didGen: true, didPrune: false}
	p, g := newRotationPKI(t, mk)

	require.NoError(t, p.rotateMixKeys(7))
	require.Equal(t, 1, mk.prunes)
	require.Equal(t, 1, g.reshadows)
}

func TestRotationDoesNotReshadowWhenNothingChanged(t *testing.T) {
	mk := &fakeMixKeys{didGen: false, didPrune: false}
	p, g := newRotationPKI(t, mk)

	require.NoError(t, p.rotateMixKeys(7))
	require.Equal(t, 0, g.reshadows)
}

func TestSkippedPublicationStillRotates(t *testing.T) {
	mk := &fakeMixKeys{didGen: true, didPrune: true}
	p, g := newRotationPKI(t, mk)
	p.advertising = false // publication gives up immediately

	require.NoError(t, p.publishDescriptorIfNeeded(context.Background()),
		"a pass with advertising off is not an error")

	require.Len(t, mk.generated, 1, "an epoch that publishes nothing still generates")
	require.Equal(t, 1, mk.prunes, "and still prunes, which is what destroys an expired key")
	require.Equal(t, 1, g.reshadows, "and reshadows the crypto workers when either changed")

	epoch, _, _ := epochtime.Now()
	require.Equal(t, epoch+1, mk.generated[0],
		"the keys generated are for the epoch after the current one")
}
