// decoy.go - Katzenpost server decoy traffic.
// Copyright (C) 2018  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package decoy implements the decoy traffic source and sink.
package decoy

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	mRand "math/rand"
	"sync"
	"time"

	"gitlab.com/yawning/avl.git"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/sphinx/path"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
	"github.com/katzenpost/katzenpost/server/internal/service/kaetzchen"
)

const maxAttempts = 3

var errMaxAttempts = errors.New("decoy: max path selection attempts exceeded")

func pathToSegments(path []*sphinx.PathHop) [][loops.SegmentIDSize]byte {
	segments := make([][loops.SegmentIDSize]byte, len(path)-1)
	for i := 0; i < len(path)-1; i++ {
		segmentID := [loops.SegmentIDSize]byte{}
		copy(segmentID[:constants.NodeIDLength], path[i].ID[:])
		copy(segmentID[constants.NodeIDLength:], path[i+1].ID[:])
		segments[i] = segmentID
	}
	return segments
}

type surbCtx struct {
	id      uint64
	eta     time.Time
	sprpKey []byte

	fwdPath []*sphinx.PathHop
	revPath []*sphinx.PathHop

	etaNode *avl.Node
}

type decoy struct {
	worker.Worker
	sync.Mutex

	sphinx *sphinx.Sphinx
	geo    *geo.Geometry

	glue glue.Glue
	log  *logging.Logger

	recipient []byte
	rng       *mRand.Rand
	docCh     chan *pkicache.Entry

	surbETAs   *avl.Tree
	surbStore  map[uint64]*surbCtx
	surbIDBase uint64

	sentLoops      map[uint64]map[[loops.SegmentIDSize]byte]int // epoch -> segment id -> count
	completedLoops map[uint64]map[[loops.SegmentIDSize]byte]int // epoch -> segment id -> count
}

func (d *decoy) gc(epoch uint64) {
	d.Lock()
	defer d.Unlock()

	delete(d.sentLoops, epoch)
	delete(d.completedLoops, epoch)
}

func (d *decoy) gcWorker() {
	timer := time.NewTimer(epochtime.Period)
	defer timer.Stop()

	for {
		var timerFired bool
		select {
		case <-d.HaltCh():
			return
		case <-timer.C:
			timerFired = true
		}
		if timerFired {
			epoch, _, _ := epochtime.Now()
			d.gc(epoch - 7)
		}
		if !timerFired && !timer.Stop() {
			select {
			case <-d.HaltCh():
				return
			case <-timer.C:
			}
		}
		timer.Reset(epochtime.Period)
	}
}

func (d *decoy) GetStats(doPublishEpoch uint64) *loops.LoopStats {
	d.Lock()

	epoch, _, _ := epochtime.Now()
	epoch = epoch - 1

	id := hash.Sum256From(d.glue.IdentityPublicKey())
	ratios := make(map[[loops.SegmentIDSize]byte]float64)

	for id, _ := range d.sentLoops[epoch] {
		sentCount, ok := d.sentLoops[epoch][id]
		if !ok {
			ratios[id] = 1
			continue
		}
		completedCount, ok := d.completedLoops[epoch][id]
		if !ok {
			ratios[id] = 1
			continue
		}
		ratios[id] = float64(completedCount) / float64(sentCount)
	}

	d.Unlock()

	return &loops.LoopStats{
		MixIdentityHash: &id,
		Epoch:           doPublishEpoch,
		SegmentRatios:   ratios,
	}
}

func (d *decoy) incrementSentSegments(fwdPath, revPath []*sphinx.PathHop) {
	d.Lock()
	defer d.Unlock()

	epoch, _, _ := epochtime.Now()
	_, ok := d.sentLoops[epoch]
	if !ok {
		d.sentLoops[epoch] = make(map[[loops.SegmentIDSize]byte]int)
	}

	fwd := pathToSegments(fwdPath)
	rev := pathToSegments(revPath)
	for i := 0; i < len(fwd); i++ {
		_, ok := d.sentLoops[epoch][fwd[i]]
		if !ok {
			d.sentLoops[epoch][fwd[i]] = 0
		}
		d.sentLoops[epoch][fwd[i]] += 1
	}
	for i := 0; i < len(rev); i++ {
		_, ok := d.sentLoops[epoch][rev[i]]
		if !ok {
			d.sentLoops[epoch][rev[i]] = 0
		}
		d.sentLoops[epoch][rev[i]] += 1
	}
}

func (d *decoy) incrementCompleted(fwdPath, revPath []*sphinx.PathHop) {
	d.Lock()
	defer d.Unlock()

	epoch, _, _ := epochtime.Now()
	_, ok := d.completedLoops[epoch]
	if !ok {
		d.completedLoops[epoch] = make(map[[loops.SegmentIDSize]byte]int)
	}

	fwd := pathToSegments(fwdPath)
	rev := pathToSegments(revPath)
	for i := 0; i < len(fwd); i++ {
		_, ok := d.completedLoops[epoch][fwd[i]]
		if !ok {
			d.completedLoops[epoch][fwd[i]] = 0
		}
		d.completedLoops[epoch][fwd[i]] += 1
	}
	for i := 0; i < len(rev); i++ {
		_, ok := d.completedLoops[epoch][rev[i]]
		if !ok {
			d.completedLoops[epoch][rev[i]] = 0
		}
		d.completedLoops[epoch][rev[i]] += 1
	}
}

func (d *decoy) OnNewDocument(ent *pkicache.Entry) {
	d.docCh <- ent
}

func (d *decoy) ExpectReply(pkt *packet.Packet) bool {
	return hmac.Equal(pkt.Recipient.ID[:], d.recipient)
}

func (d *decoy) OnPacket(pkt *packet.Packet) {
	// Note: This is called from the crypto worker context, which is "fine".
	defer pkt.Dispose()

	if !pkt.IsSURBReply() {
		panic("BUG: OnPacket called with non-SURB Reply")
	}

	// Ensure that the SURB Reply is destined for the correct recipient,
	// and that it was generated by this decoy instance.  Note that neither
	// fields are visible to any other party involved.
	if subtle.ConstantTimeCompare(pkt.Recipient.ID[:], d.recipient) != 1 {
		d.log.Debugf("Dropping packet: %v (Invalid recipient)", pkt.ID)
		instrument.PacketsDropped()
		return
	}

	idBase, id := binary.BigEndian.Uint64(pkt.SurbReply.ID[0:]), binary.BigEndian.Uint64(pkt.SurbReply.ID[8:])
	if idBase != d.surbIDBase {
		d.log.Debugf("Dropping packet: %v (Invalid SURB ID base: %v)", pkt.ID, idBase)
		instrument.PacketsDropped()
		return
	}

	d.log.Debugf("Response packet: %v", pkt.ID)

	ctx := d.loadAndDeleteSURBCtx(id)
	if ctx == nil {
		d.log.Debugf("Dropping packet: %v (Unknown SURB ID: 0x%08x)", pkt.ID, id)
		instrument.PacketsDropped()
		return
	}

	if _, err := d.sphinx.DecryptSURBPayload(pkt.Payload, ctx.sprpKey); err != nil {
		d.log.Debugf("Dropping packet: %v (SURB ID: 0x08x%): %v", pkt.ID, id, err)
		instrument.PacketsDropped()
		return
	}

	d.log.Debugf("Response packet: %v (SURB ID: 0x%08x): ETA: %v, Actual: %v (DeltaT: %v)", pkt.ID, id, ctx.eta, pkt.RecvAt, pkt.RecvAt.Sub(ctx.eta))
	d.incrementCompleted(ctx.fwdPath, ctx.revPath)
}

func (d *decoy) worker() {
	const maxDuration = math.MaxInt64

	wakeInterval := time.Duration(maxDuration)
	timer := time.NewTimer(wakeInterval)
	defer timer.Stop()

	var docCache *pkicache.Entry
	for {
		var timerFired bool
		select {
		case <-d.HaltCh():
			d.log.Debugf("Terminating gracefully.")
			return
		case newEnt := <-d.docCh:
			if !d.glue.Config().Debug.SendDecoyTraffic {
				d.log.Debugf("Received PKI document but decoy traffic is disabled, ignoring.")
				instrument.IgnoredPKIDocs()
				continue
			}

			now, _, _ := epochtime.Now()
			if entEpoch := newEnt.Epoch(); entEpoch != now {
				d.log.Debugf("Received PKI document for non-current epoch, ignoring: %v", entEpoch)
				instrument.IgnoredPKIDocs()
				continue
			}
			d.log.Debugf("Received new PKI document for epoch: %v", now)
			instrument.PKIDocs(fmt.Sprintf("%v", now))
			docCache = newEnt
		case <-timer.C:
			timerFired = true
		}

		now, _, _ := epochtime.Now()
		if docCache == nil || docCache.Epoch() != now {
			d.log.Debugf("Suspending operation till the next PKI document.")
			wakeInterval = time.Duration(maxDuration)
		} else {
			// The timer fired, and there is a valid document for this epoch.
			if timerFired {
				d.sendDecoyPacket(docCache)
			}

			// Schedule the next decoy packet.
			//
			// This closely follows how the mailproxy worker schedules
			// outgoing sends, except that the SendShift value is ignored.
			//
			// TODO: Eventually this should use separate parameters.
			isGateway := d.glue.Config().Server.IsGatewayNode

			var lambda float64
			var max uint64
			doc := docCache.Document()

			if !isGateway {
				max = doc.LambdaMMaxDelay
				lambda = doc.LambdaM
			}
			if isGateway {
				max = doc.LambdaGMaxDelay
				lambda = doc.LambdaG
			}

			wakeMsec := uint64(rand.Exp(d.rng, lambda))
			if wakeMsec > max {
				wakeMsec = max
			}
			wakeInterval = time.Duration(wakeMsec) * time.Millisecond
			d.log.Debugf("Next wakeInterval: %v", wakeInterval)

			d.sweepSURBCtxs()
		}
		if !timerFired && !timer.Stop() {
			select {
			case <-d.HaltCh():
				d.log.Debugf("Terminating gracefully.")
				return
			case <-timer.C:
			}
		}
		timer.Reset(wakeInterval)
	}
}

func (d *decoy) sendDecoyPacket(ent *pkicache.Entry) {
	// TODO: (#52) Do nothing if the rate limiter would discard the packet(?).

	selfDesc := ent.Self()
	if selfDesc.IsServiceNode {
		// The code doesn't handle this correctly yet.  It does need to
		// happen eventually though.
		panic("BUG: Service-node generated decoy traffic not supported")
	}
	doc := ent.Document()

	// TODO: The path selection maybe should be more strategic/systematic
	// rather than randomized, but this is obviously correct and leak proof.

	// Find a random Provider that is running a loop/discard service.
	var providerDesc *pki.MixDescriptor
	var loopRecip string
	for _, idx := range d.rng.Perm(len(doc.ServiceNodes)) {
		desc := doc.ServiceNodes[idx]
		params, ok := desc.Kaetzchen[kaetzchen.EchoCapability]
		if !ok {
			continue
		}
		loopRecip, ok = params["endpoint"].(string)
		if !ok {
			continue
		}
		providerDesc = desc
		break
	}
	if providerDesc == nil {
		d.log.Debugf("Failed to find suitable provider")
		return
	}

	d.sendLoopPacket(doc, []byte(loopRecip), selfDesc, providerDesc)
}

func (d *decoy) sendLoopPacket(doc *pki.Document, recipient []byte, src, dst *pki.MixDescriptor) {
	var surbID [sConstants.SURBIDLength]byte
	d.makeSURBID(&surbID)

	for attempts := 0; attempts < maxAttempts; attempts++ {
		now := time.Now()

		fwdPath, then, err := path.New(d.rng, d.geo, doc, recipient, src, dst, &surbID, time.Now(), false, true)
		if err != nil {
			d.log.Debugf("Failed to select forward path: %v", err)
			return
		}

		revPath, then, err := path.New(d.rng, d.geo, doc, d.recipient, dst, src, &surbID, then, false, false)
		if err != nil {
			d.log.Debugf("Failed to select reverse path: %v", err)
			return
		}

		if deltaT := then.Sub(now); deltaT < epochtime.Period*2 {
			zeroBytes := make([]byte, d.geo.UserForwardPayloadLength)
			payload := make([]byte, 2, 2+d.geo.SURBLength+d.geo.UserForwardPayloadLength)
			payload[0] = 1 // Packet has a SURB.

			surb, k, err := d.sphinx.NewSURB(rand.Reader, revPath)
			if err != nil {
				d.log.Debugf("Failed to generate SURB: %v", err)
			}
			payload = append(payload, surb...)
			payload = append(payload, zeroBytes...)

			// TODO: This should probably also store path information,
			// so that it's possible to figure out which links/nodes
			// are causing issues.
			ctx := &surbCtx{
				id:      binary.BigEndian.Uint64(surbID[8:]),
				eta:     time.Now().Add(deltaT),
				fwdPath: fwdPath,
				revPath: revPath,
				sprpKey: k,
			}
			d.storeSURBCtx(ctx)

			pkt, err := d.sphinx.NewPacket(rand.Reader, fwdPath, payload)
			if err != nil {
				d.log.Debugf("Failed to generate Sphinx packet: %v", err)
				return
			}

			d.logPath(doc, fwdPath)
			d.logPath(doc, revPath)
			d.log.Debugf("Dispatching loop packet: SURB ID: 0x%08x", binary.BigEndian.Uint64(surbID[8:]))

			d.dispatchPacket(fwdPath, pkt)

			d.incrementSentSegments(fwdPath, revPath)

			return
		}
	}

	d.log.Debugf("Failed to generate loop packet: %v", errMaxAttempts)
}

func (d *decoy) dispatchPacket(fwdPath []*sphinx.PathHop, raw []byte) {
	pkt, err := packet.New(raw, d.geo)
	if err != nil {
		d.log.Debugf("Failed to allocate packet: %v", err)
		return
	}
	pkt.NextNodeHop = &commands.NextNodeHop{}
	copy(pkt.NextNodeHop.ID[:], fwdPath[0].ID[:])
	pkt.DispatchAt = time.Now()

	d.log.Debugf("Dispatching packet: %v", pkt.ID)
	d.glue.Connector().DispatchPacket(pkt)
}

func (d *decoy) makeSURBID(surbID *[sConstants.SURBIDLength]byte) {
	// Generate a random SURB ID, prefixed with the time that the decoy
	// instance was initialized.

	binary.BigEndian.PutUint64(surbID[0:], d.surbIDBase)
	binary.BigEndian.PutUint64(surbID[8:], d.rng.Uint64())
}

func (d *decoy) logPath(doc *pki.Document, p []*sphinx.PathHop) error {
	s, err := path.ToString(doc, p)
	if err != nil {
		return err
	}

	for _, v := range s {
		d.log.Debug(v)
	}
	return nil
}

func (d *decoy) storeSURBCtx(ctx *surbCtx) {
	d.Lock()
	defer d.Unlock()

	ctx.etaNode = d.surbETAs.Insert(ctx)
	if ctx.etaNode.Value.(*surbCtx) != ctx {
		panic("inserting surbCtx failed, duplicate eta+id?")
	}

	d.surbStore[ctx.id] = ctx
}

func (d *decoy) loadAndDeleteSURBCtx(id uint64) *surbCtx {
	d.Lock()
	defer d.Unlock()

	ctx := d.surbStore[id]
	if ctx == nil {
		return nil
	}
	delete(d.surbStore, id)

	d.surbETAs.Remove(ctx.etaNode)
	ctx.etaNode = nil

	return ctx
}

func (d *decoy) sweepSURBCtxs() {
	d.Lock()
	defer d.Unlock()

	if d.surbETAs.Len() == 0 {
		d.log.Debugf("Sweep: No outstanding SURBs.")
		return
	}

	now := time.Now()
	slack := time.Duration(d.glue.Config().Debug.DecoySlack) * time.Millisecond
	// instead of if ctx.eta + slack > now { break } in each loop iteration
	// we precompute it:
	now_minus_slack := now.Add(-slack)

	var swept int
	iter := d.surbETAs.Iterator(avl.Forward)
	for node := iter.First(); node != nil; node = iter.Next() {
		ctx := node.Value.(*surbCtx)
		if ctx.eta.After(now_minus_slack) {
			break
		}

		delete(d.surbStore, ctx.id)

		// TODO: At some point, this should do more than just log.
		d.log.Debugf("Sweep: Lost SURB ID: 0x%08x ETA: %v (DeltaT: %v)", ctx.id, ctx.eta, now.Sub(ctx.eta))
		swept++
		// modification is unsupported EXCEPT "removing the current
		// Node", see godoc for avl/avl.go:Iterator
		d.surbETAs.Remove(node)
	}

	d.log.Debugf("Sweep: Count: %v (Removed: %v, Elapsed: %v)", len(d.surbStore), swept, time.Now().Sub(now))
}

// New constructs a new decoy instance.
func New(glue glue.Glue) (glue.Decoy, error) {
	s, err := sphinx.FromGeometry(glue.Config().SphinxGeometry)
	if err != nil {
		return nil, err
	}
	d := &decoy{
		geo:       glue.Config().SphinxGeometry,
		sphinx:    s,
		glue:      glue,
		log:       glue.LogBackend().GetLogger("decoy"),
		recipient: make([]byte, sConstants.RecipientIDLength),
		rng:       rand.NewMath(),
		docCh:     make(chan *pkicache.Entry),
		surbETAs: avl.New(func(a, b interface{}) int {
			surbCtxA, surbCtxB := a.(*surbCtx), b.(*surbCtx)
			switch {
			case surbCtxB.eta.After(surbCtxA.eta):
				return -1
			case surbCtxA.eta.After(surbCtxB.eta):
				return 1
			case surbCtxA.id < surbCtxB.id:
				return -1
			case surbCtxA.id > surbCtxB.id:
				return 1
			default:
				return 0
			}
		}),
		surbStore:      make(map[uint64]*surbCtx),
		surbIDBase:     uint64(time.Now().Unix()),
		sentLoops:      make(map[uint64]map[[loops.SegmentIDSize]byte]int),
		completedLoops: make(map[uint64]map[[loops.SegmentIDSize]byte]int),
	}
	if _, err := io.ReadFull(rand.Reader, d.recipient); err != nil {
		return nil, err
	}

	d.Go(d.worker)
	d.Go(d.gcWorker)
	return d, nil
}
