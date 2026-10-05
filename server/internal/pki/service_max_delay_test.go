// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/connlimit"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

type maxDelayRecorder struct {
	ch chan uint64
}

func (r *maxDelayRecorder) Halt()                     {}
func (r *maxDelayRecorder) OnPacket(*packet.Packet)   {}
func (r *maxDelayRecorder) OnNewMixMaxDelay(d uint64) { r.ch <- d }
func (r *maxDelayRecorder) KaetzchenForPKI() (map[string]map[string]interface{}, map[string]map[string]interface{}, error) {
	return nil, nil, nil
}

type nopConnector struct{ glue.Connector }

func (nopConnector) ForceUpdate() {}

type nopDecoy struct{ glue.Decoy }

func (nopDecoy) OnNewDocument(*pkicache.Entry) {}

type maxDelayGlue struct {
	glue.Glue
	cfg       *config.Config
	log       *log.Backend
	idKey     sign.PublicKey
	linkKey   kem.PrivateKey
	scheduler *maxDelayRecorder
	service   *maxDelayRecorder
}

func (g *maxDelayGlue) Config() *config.Config            { return g.cfg }
func (g *maxDelayGlue) LogBackend() *log.Backend          { return g.log }
func (g *maxDelayGlue) IdentityPublicKey() sign.PublicKey { return g.idKey }
func (g *maxDelayGlue) LinkKey() kem.PrivateKey           { return g.linkKey }
func (g *maxDelayGlue) MixKeys() glue.MixKeys             { return &fakeMixKeys{} }
func (g *maxDelayGlue) Scheduler() glue.Scheduler         { return g.scheduler }
func (g *maxDelayGlue) ServiceNode() glue.ServiceNode     { return g.service }
func (g *maxDelayGlue) Connector() glue.Connector         { return nopConnector{} }
func (g *maxDelayGlue) Listeners() []glue.Listener        { return nil }
func (g *maxDelayGlue) Decoy() glue.Decoy                 { return nopDecoy{} }
func (g *maxDelayGlue) PeerConnSet() *connlimit.PeerSet   { return nil }
func (g *maxDelayGlue) ReshadowCryptoWorkers()            {}

type docFetcher struct {
	doc func(epoch uint64) *cpki.Document
}

func (f *docFetcher) GetPKIDocumentForEpoch(_ context.Context, epoch uint64) (*cpki.Document, []byte, error) {
	return f.doc(epoch), []byte{1}, nil
}

func (f *docFetcher) Post(context.Context, uint64, sign.PrivateKey, sign.PublicKey, *cpki.MixDescriptor, *loops.LoopStats) error {
	return nil
}

func runWorkerWithSelf(t *testing.T, isServiceNode bool, mu float64) *maxDelayGlue {
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	idKey, _, err := signschemes.ByName("Ed25519 Sphincs+").GenerateKey()
	require.NoError(t, err)
	idBlob, err := idKey.MarshalBinary()
	require.NoError(t, err)
	_, linkKey, err := kemschemes.ByName("xwing").GenerateKeyPair()
	require.NoError(t, err)
	linkBlob, err := linkKey.Public().MarshalBinary()
	require.NoError(t, err)
	g := geo.GeometryFromUserForwardPayloadLength(nikeschemes.ByName("x25519"), 2000, true, 5)

	goo := &maxDelayGlue{
		cfg: &config.Config{
			Server:         &config.Server{Identifier: "self", IsServiceNode: isServiceNode},
			SphinxGeometry: g,
		},
		log:       backend,
		idKey:     idKey,
		linkKey:   linkKey,
		scheduler: &maxDelayRecorder{ch: make(chan uint64, 8)},
		service:   &maxDelayRecorder{ch: make(chan uint64, 8)},
	}
	p := &pki{
		glue:          goo,
		log:           backend.GetLogger("pki"),
		docs:          make(map[uint64]*pkicache.Entry),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
		impl: &docFetcher{doc: func(epoch uint64) *cpki.Document {
			self := &cpki.MixDescriptor{Name: "self", Epoch: epoch, IdentityKey: idBlob, LinkKey: linkBlob, IsServiceNode: isServiceNode}
			doc := &cpki.Document{Epoch: epoch, Mu: mu, SphinxGeometryHash: g.Hash(), Topology: [][]*cpki.MixDescriptor{{}}}
			if isServiceNode {
				doc.ServiceNodes = []*cpki.MixDescriptor{self}
			} else {
				doc.Topology[0] = []*cpki.MixDescriptor{self}
			}
			return doc
		}},
	}
	p.StartWorker()
	t.Cleanup(p.Halt)
	return goo
}

func TestWorkerPassesMixMaxDelayToServiceNode(t *testing.T) {
	t.Parallel()
	const mu = 0.005
	goo := runWorkerWithSelf(t, true, mu)
	timeout := 3*epochtime.Period/64 + 30*time.Second

	select {
	case d := <-goo.scheduler.ch:
		require.Equal(t, common.SafetyCap(mu), d)
	case <-time.After(timeout):
		t.Fatal("scheduler never got the mix max delay")
	}
	select {
	case d := <-goo.service.ch:
		require.Equal(t, common.SafetyCap(mu), d)
	case <-time.After(5 * time.Second):
		t.Fatal("service node never got the mix max delay")
	}
}

func TestWorkerSkipsServiceMaxDelayOnMix(t *testing.T) {
	t.Parallel()
	const mu = 0.005
	goo := runWorkerWithSelf(t, false, mu)
	timeout := 3*epochtime.Period/64 + 30*time.Second

	select {
	case d := <-goo.scheduler.ch:
		require.Equal(t, common.SafetyCap(mu), d)
	case <-time.After(timeout):
		t.Fatal("scheduler never got the mix max delay")
	}
	select {
	case d := <-goo.service.ch:
		t.Fatalf("a mix passed %d to the service node", d)
	case <-time.After(time.Second):
	}
}
