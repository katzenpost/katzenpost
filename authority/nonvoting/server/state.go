// state.go - Katzenpost non-voting authority server state.
// Copyright (C) 2017  Yawning Angel.
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

package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/sha3"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/authority/internal/s11n"
	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"
)

const (
	descriptorsBucket = "descriptors"
	documentsBucket   = "documents"
)

var (
	MixPublishDeadline = epochtime.Period / 4
	errGone            = errors.New("authority: Requested epoch will never get a Document")
	errNotYet          = errors.New("authority: Document is not ready yet")
	weekOfEpochs       = uint64(time.Duration(time.Hour*24*7) / epochtime.Period)
	WarpedEpoch        string
)

type descriptor struct {
	desc *pki.MixDescriptor
	raw  []byte
}

type document struct {
	doc *pki.Document
	raw []byte
}

type state struct {
	sync.RWMutex
	worker.Worker

	s   *Server
	log *logging.Logger

	db *bolt.DB

	authorizedMixes     map[[sign.PublicKeyHashSize]byte]bool
	authorizedProviders map[[sign.PublicKeyHashSize]byte]string

	documents   map[uint64]*document
	descriptors map[uint64]map[[sign.PublicKeyHashSize]byte]*descriptor
	priorSRV    [][]byte

	updateCh       chan interface{}
	bootstrapEpoch uint64
	genesisEpoch   uint64
}

func (s *state) Halt() {
	s.Worker.Halt()

	// Gracefully close the persistence store.
	s.db.Sync()
	s.db.Close()
}

func (s *state) onUpdate() {
	// Non-blocking write, multiple invocations are harmless, the channel is
	// buffered, and there is a fallback timer.
	select {
	case s.updateCh <- true:
	default:
	}
}

func (s *state) worker() {
	var wakeInterval = 60 * time.Second
	if WarpedEpoch == "true" {
		wakeInterval = 5 * time.Second
	}

	t := time.NewTicker(wakeInterval)
	defer func() {
		t.Stop()
		s.log.Debugf("Halting worker.")
	}()

	for {
		select {
		case <-s.HaltCh():
			s.log.Debugf("Terminating gracefully.")
			return
		case <-s.updateCh:
			s.log.Debugf("Wakeup due to descriptor upload.")
		case <-t.C:
			s.log.Debugf("Wakeup due to periodic timer.")
		}

		// Generate the document(s) if enough descriptors are uploaded.
		s.onWakeup()
	}
}

func (s *state) onWakeup() {
	epoch, _, till := epochtime.Now()

	s.Lock()
	defer s.Unlock()

	// If we are doing a bootstrap, and we don't have a document, attempt
	// to generate one for the current epoch regardless of the time.
	if (epoch == s.bootstrapEpoch || epoch == s.bootstrapEpoch+1) && s.documents[epoch] == nil {
		// The bootstrap phase will belatedly generate a document for
		// the current epoch iff it receives descriptor uploads for *ALL*
		// nodes it knows about (eg: Test setups).
		nrBootstrapDescs := len(s.authorizedMixes) + len(s.authorizedProviders)
		m, ok := s.descriptors[epoch]
		if ok && len(m) == nrBootstrapDescs {
			s.log.Debugf("All descriptors uploaded, bootstrapping document")
			s.generateDocument(epoch)
		} else {
			s.log.Debugf("We are in bootstrapping state for current epoch %v but only have "+
				"%d descriptors out of %d authorized nodes", epoch, len(m), nrBootstrapDescs)
		}
	}

	// If it is past the descriptor upload period and we have yet to generate a
	// document for the *next* epoch, generate one.
	if till < MixPublishDeadline && s.documents[epoch+1] == nil {
		if m, ok := s.descriptors[epoch+1]; ok && s.hasEnoughDescriptors(m) {
			s.generateDocument(epoch + 1)
		} else {
			s.log.Debugf("Not enough descriptors for next epoch %v yet", epoch+1)
		}
	}

	// Purge overly stale documents.
	s.pruneDocuments()
}

func (s *state) hasEnoughDescriptors(m map[[sign.PublicKeyHashSize]byte]*descriptor) bool {
	// A Document will be generated iff there are at least:
	//
	//  * Debug.Layers * Debug.MinNodesPerLayer nodes.
	//  * One provider.
	//
	// Otherwise, it's pointless to generate a unusable document.
	nrProviders := 0
	for _, v := range m {
		if v.desc.Layer == pki.LayerProvider {
			nrProviders++
		}
	}
	nrNodes := len(m) - nrProviders

	minNodes := s.s.cfg.Debug.Layers * s.s.cfg.Debug.MinNodesPerLayer
	return nrProviders > 0 && nrNodes >= minNodes
}

func (s *state) generateDocument(epoch uint64) {
	// Lock is held (called from the onWakeup hook).

	s.log.Noticef("Generating Document for epoch %v.", epoch)

	// Carve out the descriptors between providers and nodes.
	var providers [][]byte
	var nodes []*descriptor
	for _, v := range s.descriptors[epoch] {
		if v.desc.Layer == pki.LayerProvider {
			providers = append(providers, v.raw)
		} else {
			nodes = append(nodes, v)
		}
	}

	// Assign nodes to layers.
	var topology [][][]byte
	if d, ok := s.documents[epoch-1]; ok {
		topology = s.generateTopology(nodes, d.doc)
	} else {
		topology = s.generateRandomTopology(nodes)
	}

	// Build the Document.
	doc := &s11n.Document{
		Epoch:             epoch,
		GenesisEpoch:      s.genesisEpoch,
		SendRatePerMinute: s.s.cfg.Parameters.SendRatePerMinute,
		Mu:                s.s.cfg.Parameters.Mu,
		MuMaxDelay:        s.s.cfg.Parameters.MuMaxDelay,
		LambdaP:           s.s.cfg.Parameters.LambdaP,
		LambdaPMaxDelay:   s.s.cfg.Parameters.LambdaPMaxDelay,
		LambdaL:           s.s.cfg.Parameters.LambdaL,
		LambdaLMaxDelay:   s.s.cfg.Parameters.LambdaLMaxDelay,
		LambdaD:           s.s.cfg.Parameters.LambdaD,
		LambdaDMaxDelay:   s.s.cfg.Parameters.LambdaDMaxDelay,
		LambdaM:           s.s.cfg.Parameters.LambdaM,
		LambdaMMaxDelay:   s.s.cfg.Parameters.LambdaMMaxDelay,
		Topology:          topology,
		Providers:         providers,
	}
	// For compatibility with shared s11n implementation between voting
	// and non-voting authority, add SharedRandomValue.
	reveal := make([]byte, s11n.SharedRandomLength)

	// generate the SharedRandomValue
	rn := make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, rn)
	if err != nil || n != 32 {
		// XXX: if n != 32, err == nil
		s.s.fatalErrCh <- err
		return
	}

	binary.BigEndian.PutUint64(reveal, epoch)
	h := sha3.Sum256(rn)
	copy(reveal[8:], h[:])
	srv := sha3.New256()
	srv.Write([]byte("shared-random"))
	srv.Write(epochToBytes(epoch))
	srv.Write(s.s.IdentityKey().Bytes())
	srv.Write(reveal)

	// include last srv as hash input
	if s.genesisEpoch != epoch {
		if d, ok := s.documents[epoch-1]; ok {
			srv.Write(d.doc.SharedRandomValue)
		} else {
			s.log.Errorf("Epoch %d is not genesisEpoch %d but no prior document exists!?", epoch, s.genesisEpoch)
			s.s.fatalErrCh <- err
			return
		}
	} else {
		zeros := make([]byte, 32)
		srv.Write(zeros)
	}

	doc.SharedRandomValue = srv.Sum(nil)

	// if there are no prior SRV values, copy the current srv twice
	if len(s.priorSRV) == 0 {
		s.priorSRV = [][]byte{doc.SharedRandomValue, doc.SharedRandomValue}
	} else if (s.genesisEpoch-epoch)%weekOfEpochs == 0 {
		// rotate the weekly epochs if it is time to do so.
		s.priorSRV = [][]byte{doc.SharedRandomValue, s.priorSRV[0]}
	}
	doc.PriorSharedRandom = s.priorSRV

	// Serialize and sign the Document.
	signed, err := s11n.SignDocument(s.s.identityPrivateKey, doc)
	if err != nil {
		// This should basically always succeed.
		s.log.Errorf("Failed to sign document: %v", err)
		s.s.fatalErrCh <- err
		return
	}

	// Ensure the document is sane.
	pDoc, err := s11n.VerifyAndParseDocument([]byte(signed), s.s.identityPublicKey)
	if err != nil {
		// This should basically always succeed.
		s.log.Errorf("Signed document failed validation: %v", err)
		s.s.fatalErrCh <- err
		return
	}
	if pDoc.Epoch != epoch {
		// This should never happen either.
		s.log.Errorf("Signed document has invalid epoch: %v", pDoc.Epoch)
		s.s.fatalErrCh <- s11n.ErrInvalidEpoch
		return
	}

	s.log.Debugf("Document (Parsed): %v", pDoc)

	// Persist the document to disk.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(documentsBucket))
		bkt.Put(epochToBytes(epoch), []byte(signed))
		return nil
	}); err != nil {
		// Persistence failures are FATAL.
		s.s.fatalErrCh <- err
	}

	d := new(document)
	d.doc = pDoc
	d.raw = []byte(signed)
	s.documents[epoch] = d
}

func (s *state) generateTopology(nodeList []*descriptor, doc *pki.Document) [][][]byte {
	s.log.Debugf("Generating mix topology.")

	nodeMap := make(map[[constants.NodeIDLength]byte]*descriptor)
	for _, v := range nodeList {
		id := v.desc.IdentityKey.Sum256()
		nodeMap[id] = v
	}

	// Since there is an existing network topology, use that as the basis for
	// generating the mix topology such that the number of nodes per layer is
	// approximately equal, and as many nodes as possible retain their existing
	// layer assignment to minimise network churn.

	rng := rand.NewMath()
	targetNodesPerLayer := len(nodeList) / s.s.cfg.Debug.Layers
	topology := make([][][]byte, s.s.cfg.Debug.Layers)

	// Assign nodes that still exist up to the target size.
	for layer, nodes := range doc.Topology {
		// The existing nodes are examined in random order to make it hard
		// to predict which nodes will be shifted around.
		nodeIndexes := rng.Perm(len(nodes))
		for _, idx := range nodeIndexes {
			if len(topology[layer]) >= targetNodesPerLayer {
				break
			}

			id := nodes[idx].IdentityKey.Sum256()
			if n, ok := nodeMap[id]; ok {
				// There is a new descriptor with the same identity key,
				// as an existing descriptor in the previous document,
				// so preserve the layering.
				topology[layer] = append(topology[layer], n.raw)
				delete(nodeMap, id)
			}
		}
	}

	// Flatten the map containing the nodes pending assignment.
	toAssign := make([]*descriptor, 0, len(nodeMap))
	for _, n := range nodeMap {
		toAssign = append(toAssign, n)
	}
	assignIndexes := rng.Perm(len(toAssign))

	// Fill out any layers that are under the target size, by
	// randomly assigning from the pending list.
	idx := 0
	for layer := range doc.Topology {
		for len(topology[layer]) < targetNodesPerLayer {
			n := toAssign[assignIndexes[idx]]
			topology[layer] = append(topology[layer], n.raw)
			idx++
		}
	}

	// Assign the remaining nodes.
	for layer := 0; idx < len(assignIndexes); idx++ {
		n := toAssign[assignIndexes[idx]]
		topology[layer] = append(topology[layer], n.raw)
		layer++
		layer = layer % len(topology)
	}

	return topology
}

func (s *state) generateRandomTopology(nodes []*descriptor) [][][]byte {
	s.log.Debugf("Generating random mix topology.")

	// If there is no node history in the form of a previous consensus,
	// then the simplest thing to do is to randomly assign nodes to the
	// various layers.

	rng := rand.NewMath()
	nodeIndexes := rng.Perm(len(nodes))
	topology := make([][][]byte, s.s.cfg.Debug.Layers)
	for idx, layer := 0, 0; idx < len(nodes); idx++ {
		n := nodes[nodeIndexes[idx]]
		topology[layer] = append(topology[layer], n.raw)
		layer++
		layer = layer % len(topology)
	}

	return topology
}

func (s *state) pruneDocuments() {
	// Lock is held (called from the onWakeup hook).

	// Looking a bit into the past is probably ok, if more past documents
	// need to be accessible, then methods that query the DB could always
	// be added.
	const preserveForPastEpochs = 3

	now, _, _ := epochtime.Now()
	cmpEpoch := now - preserveForPastEpochs

	for e := range s.documents {
		if e < cmpEpoch {
			delete(s.documents, e)
		}
	}
	for e := range s.descriptors {
		if e < cmpEpoch {
			delete(s.descriptors, e)
		}
	}
}

func (s *state) isDescriptorAuthorized(desc *pki.MixDescriptor) bool {
	pk := desc.IdentityKey.Sum256()

	switch desc.Layer {
	case 0:
		return s.authorizedMixes[pk]
	case pki.LayerProvider:
		name, ok := s.authorizedProviders[pk]
		if !ok {
			return false
		}
		return name == desc.Name
	default:
		return false
	}
}

func (s *state) onDescriptorUpload(rawDesc []byte, desc *pki.MixDescriptor, epoch uint64) error {
	// Note: Caller ensures that the epoch is the current epoch +- 1.
	pk := desc.IdentityKey.Sum256()

	s.Lock()
	defer s.Unlock()

	// Get the public key -> descriptor map for the epoch.
	m, ok := s.descriptors[epoch]
	if !ok {
		m = make(map[[sign.PublicKeyHashSize]byte]*descriptor)
		s.descriptors[epoch] = m
	}

	// Check for redundant uploads.
	if d, ok := m[pk]; ok {
		// If the descriptor changes, then it will be rejected to prevent
		// nodes from reneging on uploads.
		if !bytes.Equal(d.raw, rawDesc) {
			return fmt.Errorf("state: Node %v: Conflicting descriptor for epoch %v", desc.IdentityKey, epoch)
		}

		// Redundant uploads that don't change are harmless.
		return nil
	}

	// Ok, this is a new descriptor.
	if s.documents[epoch] != nil {
		// If there is a document already, the descriptor is late, and will
		// never appear in a document, so reject it.
		return fmt.Errorf("state: Node %v: Late descriptor upload for for epoch %v", desc.IdentityKey, epoch)
	}

	// Persist the raw descriptor to disk.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(descriptorsBucket))
		eBkt, err := bkt.CreateBucketIfNotExists(epochToBytes(epoch))
		if err != nil {
			return err
		}
		eBkt.Put(pk[:], rawDesc)
		return nil
	}); err != nil {
		// Persistence failures are FATAL.
		s.s.fatalErrCh <- err
	}

	// Store the raw descriptor and the parsed struct.
	d := new(descriptor)
	d.desc = desc
	d.raw = rawDesc
	m[pk] = d

	s.log.Debugf("Node %v: Successfully submitted descriptor for epoch %v.", desc.IdentityKey, epoch)
	s.onUpdate()
	return nil
}

func (s *state) documentForEpoch(epoch uint64) ([]byte, error) {
	var generationDeadline = 7 * (epochtime.Period / 8)

	s.RLock()
	defer s.RUnlock()

	// If we have a serialized document, return it.
	if d, ok := s.documents[epoch]; ok {
		if d.raw != nil {
			return d.raw, nil
		}
		return nil, fmt.Errorf("nil document for epoch %d", epoch)
	}

	// Otherwise, return an error based on the time.
	now, elapsed, _ := epochtime.Now()
	switch epoch {
	case now:
		// Check to see if we are doing a bootstrap, and it's possible that
		// we may decide to publish a document at some point ignoring the
		// standard schedule.
		if now == s.bootstrapEpoch || now-1 == s.bootstrapEpoch {
			return nil, errNotYet
		}

		// We missed the deadline to publish a descriptor for the current
		// epoch, so we will never be able to service this request.
		s.log.Errorf("No document for current epoch %v generated and never will be", now)
		return nil, errGone
	case now + 1:
		if now == s.bootstrapEpoch {
			return nil, errNotYet
		}
		// If it's past the time by which we should have generated a document
		// then we will never be able to service this.
		if elapsed > generationDeadline {
			s.log.Errorf("No document for next epoch %v and it's already past 7/8 of previous epoch", now+1)
			return nil, errGone
		}
		return nil, errNotYet
	default:
		if epoch < now {
			// Requested epoch is in the past, and it's not in the cache.
			// We will never be able to satisfy this request.
			s.log.Errorf("No document for epoch %v, because we are already in %v", epoch, now)
			return nil, errGone
		}
		return nil, fmt.Errorf("state: Request for invalid epoch: %v", epoch)
	}

	// NOTREACHED
}

func (s *state) restorePersistence() error {
	const (
		metadataBucket = "metadata"
		versionKey     = "version"
	)

	return s.db.Update(func(tx *bolt.Tx) error {
		// Ensure that all the buckets exist.
		bkt, err := tx.CreateBucketIfNotExists([]byte(metadataBucket))
		if err != nil {
			return err
		}
		descsBkt, err := tx.CreateBucketIfNotExists([]byte(descriptorsBucket))
		if err != nil {
			return err
		}
		docsBkt, err := tx.CreateBucketIfNotExists([]byte(documentsBucket))
		if err != nil {
			return err
		}

		if b := bkt.Get([]byte(versionKey)); b != nil {
			// Well it looks like we loaded as opposed to created.
			if len(b) != 1 || b[0] != 0 {
				return fmt.Errorf("state: incompatible version: %d", uint(b[0]))
			}

			// Figure out which epochs to restore for.
			now, _, _ := epochtime.Now()
			epochs := []uint64{now - 1, now, now + 1}

			// Restore the documents and descriptors.
			for _, epoch := range epochs {
				k := epochToBytes(epoch)
				if rawDoc := docsBkt.Get(k); rawDoc != nil {
					if doc, err := s11n.VerifyAndParseDocument(rawDoc, s.s.identityPublicKey); err != nil {
						// This continues because there's no reason not to load
						// the descriptors as long as they validate, even if
						// the document fails to load.
						s.log.Errorf("Failed to validate persisted document: %v", err)
					} else if doc.Epoch != epoch {
						// The document for the wrong epoch was persisted?
						s.log.Errorf("Persisted document has unexpected epoch: %v", doc.Epoch)
					} else {
						s.log.Debugf("Restored Document for epoch %v: %v.", epoch, doc)
						d := new(document)
						d.doc = doc
						d.raw = rawDoc

						s.Lock()
						s.documents[epoch] = d
						s.Unlock()
					}
				}

				eDescsBkt := descsBkt.Bucket(k)
				if eDescsBkt == nil {
					s.log.Debugf("No persisted Descriptors for epoch: %v.", epoch)
					continue
				}

				c := eDescsBkt.Cursor()
				for pk, rawDesc := c.First(); pk != nil; pk, rawDesc = c.Next() {
					_, verifier := cert.Scheme.NewKeypair()
					err := verifier.FromBytes(pk)
					if err != nil {
						s.log.Errorf("Failed to load verifier key: %v", err)
						continue
					}
					desc, err := s11n.VerifyAndParseDescriptor(verifier, rawDesc, epoch)
					if err != nil {
						s.log.Errorf("Failed to validate persisted descriptor: %v", err)
						continue
					}
					if !bytes.Equal(pk, desc.IdentityKey.Bytes()) {
						s.log.Errorf("Discarding persisted descriptor: key mismatch")
						continue
					}

					if !s.isDescriptorAuthorized(desc) {
						s.log.Warningf("Discarding persisted descriptor: %v", desc)
						continue
					}

					s.Lock()
					m, ok := s.descriptors[epoch]
					if !ok {
						m = make(map[[sign.PublicKeyHashSize]byte]*descriptor)
						s.descriptors[epoch] = m
					}

					d := new(descriptor)
					d.desc = desc
					d.raw = rawDesc
					m[desc.IdentityKey.Sum256()] = d
					s.Unlock()

					s.log.Debugf("Restored descriptor for epoch %v: %+v", epoch, desc)
				}
			}

			return nil
		}

		// We created a new database, so populate the new `metadata` bucket.
		bkt.Put([]byte(versionKey), []byte{0})

		return nil
	})
}

func newState(s *Server) (*state, error) {
	const dbFile = "persistence.db"

	st := new(state)
	st.s = s
	st.log = s.logBackend.GetLogger("state")
	st.updateCh = make(chan interface{}, 1) // Buffered!

	// Initialize the authorized peer tables.
	st.authorizedMixes = make(map[[sign.PublicKeyHashSize]byte]bool)
	for _, v := range st.s.cfg.Mixes {
		_, idKey := cert.Scheme.NewKeypair()
		err := pem.FromFile(filepath.Join(s.cfg.Authority.DataDir, v.IdentityKeyPem), idKey)
		if err != nil {
			return nil, err
		}
		pk := idKey.Sum256()
		st.authorizedMixes[pk] = true
	}
	st.authorizedProviders = make(map[[sign.PublicKeyHashSize]byte]string)
	for _, v := range st.s.cfg.Providers {
		_, idKey := cert.Scheme.NewKeypair()
		err := pem.FromFile(filepath.Join(s.cfg.Authority.DataDir, v.IdentityKeyPem), idKey)
		if err != nil {
			return nil, err
		}
		pk := idKey.Sum256()
		st.authorizedProviders[pk] = v.Identifier
	}

	st.documents = make(map[uint64]*document)
	st.descriptors = make(map[uint64]map[[sign.PublicKeyHashSize]byte]*descriptor)

	// Initialize the persistence store and restore state.
	dbPath := filepath.Join(s.cfg.Authority.DataDir, dbFile)
	var err error
	if st.db, err = bolt.Open(dbPath, 0600, nil); err != nil {
		return nil, err
	}
	if err = st.restorePersistence(); err != nil {
		st.db.Close()
		return nil, err
	}

	// Do a "rapid" bootstrap where we will generate and publish a Document
	// for the current epoch regardless of time iff:
	//
	//  * We do not have a persisted Document for the epoch.
	//  * (Checked in worker) *All* nodes publish a descriptor.
	//
	// This could be relaxed a bit, but it's primarily intended for debugging.
	epoch, _, _ := epochtime.Now()
	d, ok := st.documents[epoch]
	if !ok {
		st.bootstrapEpoch = epoch
		st.genesisEpoch = epoch
		st.priorSRV = make([][]byte, 0)
	} else {
		st.genesisEpoch = d.doc.GenesisEpoch
		st.priorSRV = d.doc.PriorSharedRandom
	}

	st.Go(st.worker)
	return st, nil
}

func epochToBytes(e uint64) []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, e)
	return ret
}
