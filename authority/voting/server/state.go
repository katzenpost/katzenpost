// state.go - Katzenpost voting authority server state.
// Copyright (C) 2017, 2018  Yawning Angel, masala and David Stainton.
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
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	signpem "github.com/katzenpost/hpqc/sign/pem"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/katzenpost/authority/voting/client"
	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
)

const (
	descriptorsBucket     = "descriptors"
	documentsBucket       = "documents"
	stateAcceptDescriptor = "accept_desc"
	stateAcceptVote       = "accept_vote"
	stateAcceptReveal     = "accept_reveal"
	stateAcceptCert       = "accept_cert"
	stateAcceptSignature  = "accept_signature"
	stateBootstrap        = "bootstrap"

	publicKeyHashSize = 32
)

var (
	MixPublishDeadline       = epochtime.Period / 8
	AuthorityVoteDeadline    = MixPublishDeadline + epochtime.Period/8
	AuthorityRevealDeadline  = AuthorityVoteDeadline + epochtime.Period/8
	AuthorityCertDeadline    = AuthorityRevealDeadline + epochtime.Period/8
	PublishConsensusDeadline = AuthorityCertDeadline + epochtime.Period/8
	errGone                  = errors.New("authority: Requested epoch will never get a Document")
	errNotYet                = errors.New("authority: Document is not ready yet")
	errInvalidTopology       = errors.New("authority: Invalid Topology")
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
	geo *geo.Geometry
	log *logging.Logger

	db *bolt.DB

	reverseHash            map[[publicKeyHashSize]byte]sign.PublicKey
	authorizedMixes        map[[publicKeyHashSize]byte]bool
	authorizedGatewayNodes map[[publicKeyHashSize]byte]string
	authorizedServiceNodes map[[publicKeyHashSize]byte]string
	authorizedAuthorities  map[[publicKeyHashSize]byte]bool
	authorityLinkKeys      map[[publicKeyHashSize]byte]kem.PublicKey
	authorityNames         map[[publicKeyHashSize]byte]string

	documents    map[uint64]*pki.Document
	myconsensus  map[uint64]*pki.Document
	descriptors  map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor
	votes        map[uint64]map[[publicKeyHashSize]byte]*pki.Document
	certificates map[uint64]map[[publicKeyHashSize]byte]*pki.Document
	signatures   map[uint64]map[[publicKeyHashSize]byte]*cert.Signature
	priorSRV     [][]byte
	reveals      map[uint64]map[[publicKeyHashSize]byte][]byte
	commits      map[uint64]map[[publicKeyHashSize]byte][]byte
	verifiers    map[[publicKeyHashSize]byte]sign.PublicKey

	updateCh chan interface{}

	votingEpoch  uint64
	genesisEpoch uint64
	threshold    int
	dissenters   int
	state        string
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
	for {
		select {
		case <-s.HaltCh():
			s.log.Debugf("authority: Terminating gracefully.")
			return
		case <-s.fsm():
			s.log.Debugf("authority: Wakeup due to voting schedule.")
		}
	}
}

func (s *state) fsm() <-chan time.Time {
	s.Lock()
	var sleep time.Duration
	epoch, elapsed, nextEpoch := epochtime.Now()
	s.log.Debugf("Current epoch %d, remaining time: %s", epoch, nextEpoch)

	switch s.state {
	case stateBootstrap:
		s.genesisEpoch = 0
		s.backgroundFetchConsensus(epoch - 1)
		s.backgroundFetchConsensus(epoch)
		if elapsed > MixPublishDeadline {
			s.log.Errorf("Too late to vote this round, sleeping until %s", nextEpoch)
			sleep = nextEpoch
			s.votingEpoch = epoch + 2
			s.state = stateBootstrap
		} else {
			s.votingEpoch = epoch + 1
			s.state = stateAcceptDescriptor
			sleep = MixPublishDeadline - elapsed
			if sleep < 0 {
				sleep = 0
			}
			s.log.Noticef("Bootstrapping for %d", s.votingEpoch)
		}
	case stateAcceptDescriptor:
		signed, err := s.getVote(s.votingEpoch)
		if err == nil {
			serialized, err := signed.MarshalBinary()
			if err == nil {
				s.sendVoteToAuthorities(serialized, s.votingEpoch)
			} else {
				s.log.Errorf("Failed to serialize certificate for epoch %v: %s", s.votingEpoch, err)
			}
		} else {
			s.log.Errorf("Failed to compute vote for epoch %v: %s", s.votingEpoch, err)
		}
		s.state = stateAcceptVote
		_, nowelapsed, _ := epochtime.Now()
		sleep = AuthorityVoteDeadline - nowelapsed
	case stateAcceptVote:
		signed := s.reveal(s.votingEpoch)
		s.sendRevealToAuthorities(signed, s.votingEpoch)
		s.state = stateAcceptReveal
		_, nowelapsed, _ := epochtime.Now()
		sleep = AuthorityRevealDeadline - nowelapsed
	case stateAcceptReveal:
		signed, err := s.getCertificate(s.votingEpoch)
		if err == nil {
			serialized, err := signed.MarshalBinary()
			if err == nil {
				s.sendCertToAuthorities(serialized, s.votingEpoch)
			} else {
				s.log.Errorf("Failed to serialize certificate for epoch %v", s.votingEpoch)
			}
		} else {
			s.log.Errorf("Failed to compute certificate for epoch %v", s.votingEpoch)
		}
		s.state = stateAcceptCert
		_, nowelapsed, _ := epochtime.Now()
		sleep = AuthorityCertDeadline - nowelapsed
	case stateAcceptCert:
		doc, err := s.getMyConsensus(s.votingEpoch)
		if err == nil {
			s.log.Noticef("my view of consensus: %x\n%s", s.identityPubKeyHash(), doc)
			// detach signature and send to authorities
			sig, ok := doc.Signatures[s.identityPubKeyHash()]
			if !ok {
				s.log.Errorf("Failed to find our signature for epoch %v", s.votingEpoch)
				s.s.fatalErrCh <- err
				break
			}
			serialized, err := sig.Marshal()
			if err != nil {
				s.log.Errorf("Failed to serialize our signature for epoch %v", s.votingEpoch)
				s.s.fatalErrCh <- err
				break
			}
			signed, err := cert.Sign(s.s.identityPrivateKey, s.s.identityPublicKey, serialized, s.votingEpoch)
			if err != nil {
				s.log.Errorf("Failed to sign our signature for epoch %v: %s", s.votingEpoch, err)
				s.s.fatalErrCh <- err
				break
			}
			s.sendSigToAuthorities(signed, s.votingEpoch)
		} else {
			s.log.Errorf("Failed to compute our view of consensus for %v with %s", s.votingEpoch, err)
		}
		s.state = stateAcceptSignature
		_, nowelapsed, _ := epochtime.Now()
		sleep = PublishConsensusDeadline - nowelapsed
	case stateAcceptSignature:
		// combine signatures over a certificate and see if we make a threshold consensus
		s.log.Noticef("Combining signatures for epoch %v", s.votingEpoch)
		_, err := s.getThresholdConsensus(s.votingEpoch)
		_, _, nextEpoch := epochtime.Now()
		if err == nil {
			s.state = stateAcceptDescriptor
			sleep = MixPublishDeadline + nextEpoch
			s.votingEpoch++
		} else {
			s.log.Error(err.Error())
			s.state = stateBootstrap
			s.votingEpoch = epoch + 2 // vote on epoch+2 in epoch+1
			sleep = nextEpoch
		}
	default:
	}
	s.pruneDocuments()
	s.log.Debugf("authority: FSM in state %v until %s", s.state, sleep)
	s.Unlock()
	return time.After(sleep)
}

func (s *state) persistDocument(epoch uint64, doc []byte) {
	if err := s.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(documentsBucket))
		return bkt.Put(epochToBytes(epoch), doc)
	}); err != nil {
		// Persistence failures are FATAL.
		s.s.fatalErrCh <- err
	}
}

// getVote produces a pki.Document using all MixDescriptors that we have seen
func (s *state) getVote(epoch uint64) (*pki.Document, error) {
	// Is there a prior consensus? If so, obtain the GenesisEpoch and prior SRV values
	if d, ok := s.documents[s.votingEpoch-1]; ok {
		s.log.Debugf("Restoring genesisEpoch %d from document cache", d.GenesisEpoch)
		s.genesisEpoch = d.GenesisEpoch
		s.priorSRV = d.PriorSharedRandom
		d.PKISignatureScheme = s.s.cfg.Server.PKISignatureScheme
	} else {
		s.log.Debugf("Setting genesisEpoch %d from votingEpoch", s.votingEpoch)
		s.genesisEpoch = s.votingEpoch
	}

	descriptors := []*pki.MixDescriptor{}
	for _, desc := range s.descriptors[epoch] {
		descriptors = append(descriptors, desc)
	}

	// vote topology is irrelevent.
	var zeros [32]byte
	vote := s.getDocument(descriptors, s.s.cfg.Parameters, zeros[:])

	// create our SharedRandom Commit
	signedCommit, err := s.doCommit(epoch)
	if err != nil {
		return nil, err
	}
	commits := make(map[[hash.HashSize]byte][]byte)
	commits[s.identityPubKeyHash()] = signedCommit
	vote.SharedRandomCommit = commits

	_, err = s.doSignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, vote)
	if err != nil {
		return nil, err
	}

	s.log.Debugf("Ready to send our vote:\n%s", vote)
	// save our own vote
	if _, ok := s.votes[epoch]; !ok {
		s.votes[epoch] = make(map[[publicKeyHashSize]byte]*pki.Document)
	}
	if _, ok := s.votes[epoch][s.identityPubKeyHash()]; !ok {
		s.votes[epoch][s.identityPubKeyHash()] = vote
	} else {
		return nil, errors.New("failure: vote already present, this should never happen")
	}
	return vote, nil
}

func (s *state) doParseDocument(b []byte) (*pki.Document, error) {
	doc, err := pki.ParseDocument(b)
	return doc, err
}

func (s *state) doSignDocument(signer sign.PrivateKey, verifier sign.PublicKey, d *pki.Document) ([]byte, error) {
	signAt := time.Now()
	sig, err := pki.SignDocument(signer, verifier, d)
	s.log.Noticef("pki.SignDocument took %v", time.Since(signAt))
	return sig, err
}

// getCertificate is the same as a vote but it contains all SharedRandomCommits and SharedRandomReveals seen
func (s *state) getCertificate(epoch uint64) (*pki.Document, error) {
	if s.TryLock() {
		panic("write lock not held in getCertificate(epoch)")
	}

	mixes, params, err := s.tallyVotes(epoch)
	if err != nil {
		s.log.Warningf("No document for epoch %v, aborting!, %v", epoch, err)
		return nil, err
	}
	s.log.Debug("Mixes tallied, now making a document")
	var zeros [32]byte
	srv := zeros[:]
	certificate := s.getDocument(mixes, params, srv)
	// add the SharedRandomCommit and SharedRandomReveal that we have seen
	certificate.SharedRandomCommit = s.commits[epoch]
	certificate.SharedRandomReveal = s.reveals[epoch]
	// if there are no prior SRV values, copy the current srv twice
	if len(s.priorSRV) == 0 {
		s.priorSRV = [][]byte{srv, srv}
	} else if epoch%epochtime.WeekOfEpochs == 0 {
		// rotate the weekly epochs if it is time to do so.
		s.priorSRV = [][]byte{srv, s.priorSRV[0]}
	}
	_, err = s.doSignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, certificate)
	if err != nil {
		return nil, err
	}
	err = pki.IsDocumentWellFormed(certificate, s.getVerifiers())
	if err != nil {
		return nil, err
	}
	// save our own certificate
	if _, ok := s.certificates[epoch]; !ok {
		s.certificates[epoch] = make(map[[publicKeyHashSize]byte]*pki.Document)
	}
	if _, ok := s.certificates[epoch][s.identityPubKeyHash()]; !ok {
		s.certificates[epoch][s.identityPubKeyHash()] = certificate
	} else {
		return nil, errors.New("failure: vote already present, this should never happen")
	}
	return certificate, nil
}

// getConsensus computes the final document using the computed SharedRandomValue
func (s *state) getMyConsensus(epoch uint64) (*pki.Document, error) {
	if s.TryLock() {
		panic("write lock not held in getMyConsensus(epoch)")
	}

	certificates, ok := s.certificates[epoch]
	if !ok {
		return nil, fmt.Errorf("No certificates for epoch %d", epoch)
	}

	// well this isn't going to work then is it?
	if len(certificates) < s.threshold {
		return nil, fmt.Errorf("No way to make consensus with too few votes!, only %d certificates", len(certificates))
	}

	// verify that all shared random commit and reveal are present for this epoch
	commits, reveals := s.verifyCommits(epoch)
	if len(commits) < s.threshold {
		return nil, fmt.Errorf("No way to make consensus with too few SharedRandom commits!, only %d commits", len(commits))
	}
	if len(commits) != len(reveals) {
		panic("ShouldNotBePossible")
	}

	// compute the shared random for the consensus
	srv, err := s.computeSharedRandom(epoch, commits, reveals)
	if err != nil {
		return nil, err
	}
	// if there are no prior SRV values, copy the current srv twice
	if epoch == s.genesisEpoch {
		s.priorSRV = [][]byte{srv, srv}
	} else if epoch%epochtime.WeekOfEpochs == 0 {
		// rotate the weekly epochs if it is time to do so.
		s.priorSRV = [][]byte{srv, s.priorSRV[0]}
	}
	mixes, params, err := s.tallyVotes(epoch)
	if err != nil {
		return nil, err
	}
	consensusOfOne := s.getDocument(mixes, params, srv)
	_, err = s.doSignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, consensusOfOne)
	if err != nil {
		return nil, err
	}

	// save our view of the conseusus
	s.myconsensus[epoch] = consensusOfOne
	return consensusOfOne, nil
}

// getThresholdConsensus returns a *pki.Document iff a threshold consensus is reached or error
func (s *state) getThresholdConsensus(epoch uint64) (*pki.Document, error) {
	// range over the certificates we have collected and see if we can collect enough signatures to make a consensus
	if s.TryLock() {
		panic("write lock not held in getThresholdConsensus(epoch)")
	}

	ourConsensus, ok := s.myconsensus[epoch]
	if !ok {
		return nil, fmt.Errorf("We have no view of consensus!")
	}
	for pk, signature := range s.signatures[epoch] {
		s.log.Debugf("Checking signature from %x on our certificates", pk)
		v := s.reverseHash[pk]
		err := ourConsensus.AddSignature(v, *signature)
		if err != nil {
			s.log.Errorf("Failed to AddSignature from %x on our consensus: %s", pk, err)
		}
	}
	// now see if we managed to get a threshold number of signatures
	signedConsensus, err := ourConsensus.MarshalBinary()
	if err != nil {
		return nil, err
	}
	_, good, bad, err := cert.VerifyThreshold(s.getVerifiers(), s.threshold, signedConsensus)
	for _, b := range bad {
		s.log.Errorf("Consensus NOT signed by %s", s.authorityNames[hash.Sum256From(b)])
	}
	for _, g := range good {
		s.log.Noticef("Consensus signed by %s", s.authorityNames[hash.Sum256From(g)])
	}
	if err == nil {
		s.log.Noticef("Consensus made for epoch %d with %d/%d signatures: %v", epoch, len(good), len(s.verifiers), ourConsensus)
		// Persist the document to disk.
		s.persistDocument(epoch, signedConsensus)
		s.documents[epoch] = ourConsensus
		return ourConsensus, nil
	} else {
		s.log.Errorf("VerifyThreshold failed!: %s", err)
	}
	return nil, fmt.Errorf("No consensus found for epoch %d", epoch)
}

func (s *state) getVerifiers() []sign.PublicKey {
	v := make([]sign.PublicKey, len(s.verifiers))
	i := 0
	for _, val := range s.verifiers {
		v[i] = val
		i++
	}
	return v
}

func (s *state) identityPubKeyHash() [publicKeyHashSize]byte {
	return hash.Sum256From(s.s.identityPublicKey)
}

func (s *state) getDocument(descriptors []*pki.MixDescriptor, params *config.Parameters, srv []byte) *pki.Document {
	// Carve out the descriptors between providers and nodes.
	gateways := []*pki.MixDescriptor{}
	serviceNodes := []*pki.MixDescriptor{}
	nodes := []*pki.MixDescriptor{}

	for _, v := range descriptors {
		if v.IsGatewayNode {
			gateways = append(gateways, v)
		} else if v.IsServiceNode {
			serviceNodes = append(serviceNodes, v)
		} else {
			nodes = append(nodes, v)
		}
	}

	// Assign nodes to layers.
	var topology [][]*pki.MixDescriptor

	// if a static topology is specified, generate a fixed topology
	if s.s.cfg.Topology != nil {
		topology = s.generateFixedTopology(nodes, srv)
	} else {
		// We prefer to not randomize the topology if there is an existing topology to avoid
		// partitioning the client anonymity set when messages from an earlier epoch are
		// differentiable as such because of topology violations in the present epoch.

		if d, ok := s.documents[s.votingEpoch-1]; ok {
			topology = s.generateTopology(nodes, d, srv)
		} else {
			topology = s.generateRandomTopology(nodes, srv)
		}
	}

	lambdaG := computeLambdaG(s.s.cfg)
	s.log.Debugf("computed lambdaG is %f", lambdaG)

	// Build the Document.
	doc := &pki.Document{
		Epoch:              s.votingEpoch,
		GenesisEpoch:       s.genesisEpoch,
		SendRatePerMinute:  params.SendRatePerMinute,
		Mu:                 params.Mu,
		MuMaxDelay:         params.MuMaxDelay,
		LambdaP:            params.LambdaP,
		LambdaPMaxDelay:    params.LambdaPMaxDelay,
		LambdaL:            params.LambdaL,
		LambdaLMaxDelay:    params.LambdaLMaxDelay,
		LambdaD:            params.LambdaD,
		LambdaDMaxDelay:    params.LambdaDMaxDelay,
		LambdaM:            params.LambdaM,
		LambdaMMaxDelay:    params.LambdaMMaxDelay,
		LambdaG:            lambdaG,
		LambdaGMaxDelay:    params.LambdaGMaxDelay,
		Topology:           topology,
		GatewayNodes:       gateways,
		ServiceNodes:       serviceNodes,
		SharedRandomValue:  srv,
		PriorSharedRandom:  s.priorSRV,
		SphinxGeometryHash: s.geo.Hash(),
		PKISignatureScheme: s.s.cfg.Server.PKISignatureScheme,
	}
	return doc
}

func (s *state) hasEnoughDescriptors(m map[[publicKeyHashSize]byte]*pki.MixDescriptor) bool {
	// A Document will be generated iff there are at least:
	//
	//  * Debug.Layers * Debug.MinNodesPerLayer nodes.
	//  * One gateway.
	//  * One service node.
	//
	// Otherwise, it's pointless to generate a unusable document.
	nrGateways := 0
	nrServiceNodes := 0
	for _, v := range m {
		if v.IsGatewayNode {
			nrGateways++
		}
		if v.IsServiceNode {
			nrServiceNodes++
		}

	}
	nrNodes := len(m) - nrGateways - nrServiceNodes

	minNodes := s.s.cfg.Debug.Layers * s.s.cfg.Debug.MinNodesPerLayer
	return (nrGateways > 0) && (nrServiceNodes > 0) && (nrNodes >= minNodes)
}

func (s *state) verifyCommits(epoch uint64) (map[[publicKeyHashSize]byte][]byte, map[[publicKeyHashSize]byte][]byte) {
	if s.TryLock() {
		panic("write lock not held in verifyCommits(epoch)")
	}

	// check that each authority presented the same commit to every other authority
	badnodes := make(map[[publicKeyHashSize]byte]bool)
	comitted := make(map[[publicKeyHashSize]byte][]byte)
	revealed := make(map[[publicKeyHashSize]byte][]byte)

	// verify that each authority only submitted one commit value to all the authorities
	for pk, certificate := range s.certificates[epoch] {
		// skip badnodes
		if _, ok := badnodes[pk]; ok {
			continue
		}
		for pk2, signedCommit := range certificate.SharedRandomCommit {
			// skip badnodes
			if _, ok := badnodes[pk2]; ok {
				continue
			}
			// verify that pk2 is authorized
			v, ok := s.reverseHash[pk2]
			if !ok {
				s.log.Errorf("Commit from invaid peer %x in certificate from %s", pk2, s.authorityNames[pk])
				badnodes[pk] = true
				break
			}
			// verify that the allged commit is signed by pk2
			commit, err := cert.Verify(v, signedCommit)
			if err != nil {
				// pk didn't validate commit in its certificate!
				badnodes[pk] = true
				s.log.Errorf("Invalid signature over commit from %s in certificate from %s, rejecting %s from consensus", s.authorityNames[pk2], s.authorityNames[pk], s.authorityNames[pk])
				// do not bother checking any more of pk's SharedRandomCommits
				break
			}
			// verify that the commit is accompanied by a reaveal
			signedReveal, ok := certificate.SharedRandomReveal[pk2]
			if !ok {
				s.log.Errorf("Certificate from %s has Commit for %s but not Reveal", s.authorityNames[pk], s.authorityNames[pk2])
				badnodes[pk] = true
				// do not bother checking any more of pk's SharedRandomCommits
				break
			}
			// verify that the alleged reveal is signed by pk2
			reveal, err := cert.Verify(v, signedReveal)
			if err != nil {
				s.log.Errorf("Reveal in certificate from %s has invalid signature on reveal from %s", s.authorityNames[pk], s.authorityNames[pk2])
				badnodes[pk] = true
				// do not bother checking any more of pk's SharedRandomCommits
				break
			}
			srv := new(pki.SharedRandom)
			srv.SetCommit(commit)
			// verify that the SharedRandom is for the correct epoch
			if srv.GetEpoch() != epoch {
				s.log.Errorf("SharedRandomCommit in certificate from %s contains bad Epoch from %s", s.authorityNames[pk], s.authorityNames[pk2])
				badnodes[pk] = true
				badnodes[pk2] = true
				// do not bother checking any more of pk's SharedRandomCommits
				break
			}

			// verify that the commit is validate by the revealed value
			if !srv.Verify(reveal) {
				s.log.Errorf("Reveal in certificate from %s has invalid reveal from %s", s.authorityNames[pk], s.authorityNames[pk2])
				// pk should have validated the Reveal, and pk2 signed an invalid Reveal
				badnodes[pk] = true
				badnodes[pk2] = true
				break
			}
			// see if we saw a different commit from pk2
			signedCommit2, ok := comitted[pk2]
			if ok {
				// check that the commits were the same
				if !bytes.Equal(signedCommit, signedCommit2) {
					s.log.Errorf("%s submitted commit %x to %s and previously submitted %x", s.authorityNames[pk2], signedCommit[:32], s.authorityNames[pk], signedCommit2[:32])
					badnodes[pk2] = true
				}
			} else {
				// first time we saw a commit from pk2
				comitted[pk2] = signedCommit
			}
			// see if we saw a different reveal from pk2
			signedReveal2, ok := revealed[pk2]
			if ok {
				if !bytes.Equal(signedReveal, signedReveal2) {
					s.log.Errorf("%s submitted commit %x to %s and previously submitted %x", s.authorityNames[pk2], signedReveal, s.authorityNames[pk], signedReveal2)
					badnodes[pk2] = true
				}
			} else {
				revealed[pk2] = signedReveal
			}
		}
	}
	// ensure we have enough commits to make a threshold consensus
	for pk, _ := range badnodes {
		s.log.Warningf("Found bad node %s", s.authorityNames[pk])
		delete(comitted, pk)
		delete(revealed, pk)
	}
	return comitted, revealed
}

// IsPeerValid authenticates the remote peer's credentials
// for our link layer wire protocol as specified by
// the PeerAuthenticator interface in core/wire/session.go
func (s *state) IsPeerValid(creds *wire.PeerCredentials) bool {
	var ad [publicKeyHashSize]byte
	copy(ad[:], creds.AdditionalData[:publicKeyHashSize])
	_, ok := s.authorizedAuthorities[ad]
	if ok {
		return true
	}
	return false
}

func (s *state) sendCommandToPeer(peer *config.Authority, cmd commands.Command) (commands.Command, error) {
	var conn net.Conn
	var err error
	for i, a := range peer.Addresses {
		conn, err = net.Dial("tcp", a)
		if err == nil {
			break
		}
		if i == len(peer.Addresses)-1 {
			return nil, err
		}
	}
	defer conn.Close()
	s.s.Add(1)
	defer s.s.Done()
	identityHash := hash.Sum256From(s.s.identityPublicKey)

	kemscheme := schemes.ByName(s.s.cfg.Server.WireKEMScheme)
	if kemscheme == nil {
		panic("kem scheme not found in registry")
	}

	cfg := &wire.SessionConfig{
		KEMScheme:         kemscheme,
		Geometry:          s.geo,
		Authenticator:     s,
		AdditionalData:    identityHash[:],
		AuthenticationKey: s.s.linkKey,
		RandomReader:      rand.Reader,
	}
	session, err := wire.NewPKISession(cfg, true)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	if err = session.Initialize(conn); err != nil {
		return nil, err
	}
	err = session.SendCommand(cmd)
	if err != nil {
		return nil, err
	}
	resp, err := session.RecvCommand()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// sendCommitToAuthorities sends our cert to all Directory Authorities
func (s *state) sendCertToAuthorities(cert []byte, epoch uint64) {
	if s.TryLock() {
		panic("write lock not held in sendCertToAuthorities(cert, epoch)")
	}

	s.log.Noticef("Sending Certificate for epoch %v, to all Directory Authorities.", epoch)
	cmd := &commands.Cert{
		Epoch:     epoch,
		PublicKey: s.s.IdentityKey(),
		Payload:   cert,
	}

	for _, peer := range s.s.cfg.Authorities {
		peer := peer
		if peer.IdentityPublicKey.Equal(s.s.identityPublicKey) {
			continue // skip self
		}
		go func() {
			s.log.Noticef("Sending cert to %s", peer.Identifier)
			resp, err := s.sendCommandToPeer(peer, cmd)
			if err != nil {
				s.log.Error("Failed to send cert to %s", peer.Identifier)
				return
			}
			r, ok := resp.(*commands.CertStatus)
			if !ok {
				s.log.Warningf("Cert response resulted in unexpected reply: %T", resp)
				return
			}
			switch r.ErrorCode {
			case commands.CertOk:
				s.log.Notice("Cert submitted to %s", peer.Identifier)
			case commands.CertTooLate:
				s.log.Warningf("Cert rejected with CertTooLate by %s", peer.Identifier)
			case commands.CertTooEarly:
				s.log.Warningf("Cert rejected with CertTooEarly by %s", peer.Identifier)
			case commands.CertAlreadyReceived:
				s.log.Warningf("Cert rejected with CertAlreadyReceived by %s", peer.Identifier)
			case commands.CertNotAuthorized:
				s.log.Warningf("Cert rejected with CertNotAuthoritzed by %s", peer.Identifier)
			case commands.CertNotSigned:
				s.log.Warningf("Cert rejected with CertNotSigned by %s", peer.Identifier)
			default:
				s.log.Warningf("Cert rejected with unknown error code received by %s", peer.Identifier)
			}
		}()
	}
}

// sendVoteToAuthorities sends s.descriptors[epoch] to all Directory Authorities
func (s *state) sendVoteToAuthorities(vote []byte, epoch uint64) {
	if s.TryLock() {
		panic("write lock not held in sendVoteToAuthorities(vote, epoch)")
	}

	s.log.Noticef("Sending Vote for epoch %v, to all Directory Authorities.", epoch)

	cmd := &commands.Vote{
		Epoch:     epoch,
		PublicKey: s.s.IdentityKey(),
		Payload:   vote,
	}

	for _, peer := range s.s.cfg.Authorities {
		peer := peer
		if peer.IdentityPublicKey.Equal(s.s.identityPublicKey) {
			continue // skip self
		}
		go func() {
			s.log.Noticef("Sending Vote to %s", peer.Identifier)
			resp, err := s.sendCommandToPeer(peer, cmd)
			if err != nil {
				s.log.Error("Failed to send vote to %s", peer.Identifier)
				return
			}
			r, ok := resp.(*commands.VoteStatus)
			if !ok {
				s.log.Warningf("Vote response resulted in unexpected reply: %T", resp)
				return
			}
			switch r.ErrorCode {
			case commands.VoteOk:
				s.log.Notice("Vote submitted to %s", peer.Identifier)
			case commands.VoteTooLate:
				s.log.Warningf("Vote rejected with VoteTooLate by %s", peer.Identifier)
			case commands.VoteTooEarly:
				s.log.Warningf("Vote rejected with VoteTooEarly by %s", peer.Identifier)
			default:
				s.log.Warningf("Vote rejected with unknown error code received by %s", peer.Identifier)
			}
		}()
	}
}

// sendRevealToAuthorities sends a Shared Random Reveal command to
// all Directory Authorities
func (s *state) sendRevealToAuthorities(reveal []byte, epoch uint64) {
	s.log.Noticef("Sending Shared Random Reveal for epoch %v, to all Directory Authorities.", epoch)

	cmd := &commands.Reveal{
		Epoch:     epoch,
		PublicKey: s.s.IdentityKey(),
		Payload:   reveal,
	}
	for _, peer := range s.s.cfg.Authorities {
		peer := peer
		if peer.IdentityPublicKey.Equal(s.s.identityPublicKey) {
			continue // skip self
		}
		go func() {
			s.log.Noticef("Sending Reveal to %s", peer.Identifier)
			resp, err := s.sendCommandToPeer(peer, cmd)
			if err != nil {
				s.log.Error("Failed to send reveal to %s", peer.Identifier)
				return
			}
			r, ok := resp.(*commands.RevealStatus)
			if !ok {
				s.log.Error("Reveal response resulted in unexpected reply: %T", resp)
				return
			}
			switch r.ErrorCode {
			case commands.RevealOk:
				s.log.Notice("Reveal submitted to %s", peer.Identifier)
			case commands.RevealTooLate:
				s.log.Warningf("Reveal rejected with RevealTooLate by %s", peer.Identifier)
			case commands.RevealTooEarly:
				s.log.Warningf("Reveal rejected with RevealTooEarly by %s", peer.Identifier)
			case commands.RevealAlreadyReceived:
				s.log.Warningf("Reveal rejected with RevealAlreadyReceived by %s", peer.Identifier)
			case commands.RevealNotAuthorized:
				s.log.Warningf("Reveal rejected with RevealNotAuthoritzed by %s", peer.Identifier)
			case commands.RevealNotSigned:
				s.log.Warningf("Reveal rejected with RevealNotSigned by %s", peer.Identifier)
			default:
				s.log.Warningf("reveal rejected with unknown error code received by %s", peer.Identifier)
			}
		}()
	}
}

func (s *state) sendSigToAuthorities(sig []byte, epoch uint64) {
	if s.TryLock() {
		panic("write lock not held in sendSigToAuthorities(sig, epoch)")
	}

	s.log.Noticef("Sending Signature for epoch %v, to all Directory Authorities.", epoch)

	cmd := &commands.Sig{
		Epoch:     epoch,
		PublicKey: s.s.IdentityKey(),
		Payload:   sig,
	}

	for _, peer := range s.s.cfg.Authorities {
		peer := peer
		if peer.IdentityPublicKey.Equal(s.s.identityPublicKey) {
			continue // skip self
		}
		go func() {
			s.log.Noticef("Sending Signature to %s", peer.Identifier)
			resp, err := s.sendCommandToPeer(peer, cmd)
			if err != nil {
				s.log.Error("Failed to send Signature to %s", peer.Identifier)
				return
			}
			r, ok := resp.(*commands.SigStatus)
			if !ok {
				s.log.Warningf("Signature resulted in unexpected reply: %T", resp)
				return
			}
			switch r.ErrorCode {
			case commands.SigOk:
				s.log.Notice("Signature submitted to %s", peer.Identifier)
			case commands.SigTooLate:
				s.log.Warningf("Signature rejected with SigTooLate by %s", peer.Identifier)
			case commands.SigTooEarly:
				s.log.Warningf("Signature rejected with SigTooEarly by %s", peer.Identifier)
			default:
				s.log.Warningf("Signature rejected with unknown error code received by %s", peer.Identifier)
			}
		}()
	}
}

func (s *state) tallyVotes(epoch uint64) ([]*pki.MixDescriptor, *config.Parameters, error) {
	if s.TryLock() {
		panic("write lock not held in tallyVotes(epoch)")
	}

	_, ok := s.votes[epoch]
	if !ok {
		return nil, nil, fmt.Errorf("no votes for epoch %v", epoch)
	}
	if len(s.votes[epoch]) < s.threshold {
		return nil, nil, fmt.Errorf("not enough votes for epoch %v", epoch)
	}

	nodes := make([]*pki.MixDescriptor, 0)
	mixTally := make(map[string][]*pki.Document)
	mixParams := make(map[string][]*pki.Document)
	for id, vote := range s.votes[epoch] {
		// serialize the vote parameters and tally these as well.
		params := &config.Parameters{
			SendRatePerMinute: vote.SendRatePerMinute,
			Mu:                vote.Mu,
			MuMaxDelay:        vote.MuMaxDelay,
			LambdaP:           vote.LambdaP,
			LambdaPMaxDelay:   vote.LambdaPMaxDelay,
			LambdaL:           vote.LambdaL,
			LambdaLMaxDelay:   vote.LambdaLMaxDelay,
			LambdaD:           vote.LambdaD,
			LambdaDMaxDelay:   vote.LambdaDMaxDelay,
			LambdaM:           vote.LambdaM,
			LambdaMMaxDelay:   vote.LambdaMMaxDelay,
			LambdaG:           computeLambdaG(s.s.cfg),
			LambdaGMaxDelay:   vote.LambdaGMaxDelay,
		}
		b := bytes.Buffer{}
		e := gob.NewEncoder(&b)
		err := e.Encode(params)
		if err != nil {
			s.log.Errorf("Skipping vote from Authority %s whose MixParameters failed to encode?! %v", s.authorityNames[id], err)
			continue
		}
		bs := b.String()
		if _, ok := mixParams[bs]; !ok {
			mixParams[bs] = make([]*pki.Document, 0)
		}
		mixParams[bs] = append(mixParams[bs], vote)

		// include edge nodes in the tally.
		for _, desc := range vote.GatewayNodes {
			rawDesc, err := desc.MarshalBinary()
			if err != nil {
				s.log.Errorf("Skipping vote from Authority %s whose MixDescriptor failed to encode?! %v", s.authorityNames[id], err)
				continue
			}
			k := string(rawDesc)
			if _, ok := mixTally[k]; !ok {
				mixTally[k] = make([]*pki.Document, 0)
			}
			mixTally[k] = append(mixTally[k], vote)
		}
		for _, desc := range vote.ServiceNodes {
			rawDesc, err := desc.MarshalBinary()
			if err != nil {
				s.log.Errorf("Skipping vote from Authority %s whose MixDescriptor failed to encode?! %v", s.authorityNames[id], err)
				continue
			}
			k := string(rawDesc)
			if _, ok := mixTally[k]; !ok {
				mixTally[k] = make([]*pki.Document, 0)
			}
			mixTally[k] = append(mixTally[k], vote)
		}
		// include the rest of the mixes in the tally.
		for _, l := range vote.Topology {
			for _, desc := range l {
				rawDesc, err := desc.MarshalBinary()
				if err != nil {
					s.log.Errorf("Skipping vote from Authority %s whose MixDescriptor failed to encode?! %v", s.authorityNames[id], err)
					continue
				}

				k := string(rawDesc)
				if _, ok := mixTally[k]; !ok {
					mixTally[k] = make([]*pki.Document, 0)
				}
				mixTally[k] = append(mixTally[k], vote)
			}
		}
	}
	// include mixes that have a threshold of votes
	for rawDesc, votes := range mixTally {
		if len(votes) >= s.threshold {
			// this shouldn't fail as the descriptors have already been verified
			desc := new(pki.MixDescriptor)
			err := desc.UnmarshalBinary([]byte(rawDesc))
			if err != nil {
				return nil, nil, err
			}
			// only add nodes we have authorized
			if s.isDescriptorAuthorized(desc) {
				nodes = append(nodes, desc)
			}
		}
	}
	// include parameters that have a threshold of votes
	for bs, votes := range mixParams {
		params := &config.Parameters{}
		d := gob.NewDecoder(strings.NewReader(bs))
		if err := d.Decode(params); err != nil {
			s.log.Errorf("tallyVotes: failed to decode params: err=%v: bs=%v", err, bs)
			continue
		}

		if len(votes) >= s.threshold {
			sortNodesByPublicKey(nodes)
			// successful tally
			return nodes, params, nil
		} else if len(votes) >= s.dissenters {
			s.log.Errorf("tallyVotes: failed threshold with params: %v", params)
			continue
		}

	}
	return nil, nil, errors.New("consensus failure (mixParams empty)")
}

func (s *state) computeSharedRandom(epoch uint64, commits map[[publicKeyHashSize]byte][]byte, reveals map[[publicKeyHashSize]byte][]byte) ([]byte, error) {
	if len(commits) < s.threshold {
		s.log.Errorf("Insufficient commits for epoch %d to make consensus", epoch)
		for id, _ := range commits {
			s.log.Errorf("Have commits for epoch %d from %x", epoch, id)
		}
		return nil, errors.New("Insuffiient commits to make threshold vote")
	}
	type Reveal struct {
		PublicKey [publicKeyHashSize]byte
		Digest    []byte
	}
	sortedreveals := make([]Reveal, 0, len(reveals))
	for pk, srr := range reveals {
		digest, err := cert.GetCertified(srr)
		if err != nil {
			return nil, err
		}
		sortedreveals = append(sortedreveals, Reveal{PublicKey: pk, Digest: digest})
	}
	srv, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}

	srv.Write([]byte("shared-random"))
	srv.Write(epochToBytes(epoch))

	sort.Slice(sortedreveals, func(i, j int) bool {
		return string(sortedreveals[i].Digest) > string(sortedreveals[j].Digest)
	})

	for _, reveal := range sortedreveals {
		srv.Write(reveal.PublicKey[:])
		srv.Write(reveal.Digest)
	}
	// XXX: Tor also hashes in the previous srv or 32 bytes of 0x00
	//      How do we bootstrap a new authority?
	zeros := make([]byte, 32)
	if vot, ok := s.documents[s.votingEpoch-1]; ok {
		srv.Write(vot.SharedRandomValue)
	} else {
		srv.Write(zeros)
	}
	return srv.Sum(nil), nil
}

func (s *state) generateTopology(nodeList []*pki.MixDescriptor, doc *pki.Document, srv []byte) [][]*pki.MixDescriptor {
	s.log.Debugf("Generating mix topology.")

	nodeMap := make(map[[constants.NodeIDLength]byte]*pki.MixDescriptor)
	for _, v := range nodeList {
		id := hash.Sum256(v.IdentityKey)
		nodeMap[id] = v
	}

	// TODO: consider strategies for balancing topology? Should this happen automatically?
	//       the current strategy will rebalance by limiting the number of nodes that are
	//       (re)inserted at each layer and placing these nodes into another layer.

	// Since there is an existing network topology, use that as the basis for
	// generating the mix topology such that the number of nodes per layer is
	// approximately equal, and as many nodes as possible retain their existing
	// layer assignment to minimise network churn.
	// The srv is used, when available, to ensure the ordering of new nodes
	// is deterministic between authorities
	rng, err := rand.NewDeterministicRandReader(srv[:])
	if err != nil {
		s.log.Errorf("DeterministicRandReader() failed to initialize: %v", err)
		s.s.fatalErrCh <- err
	}
	targetNodesPerLayer := len(nodeList) / s.s.cfg.Debug.Layers
	topology := make([][]*pki.MixDescriptor, s.s.cfg.Debug.Layers)

	// Assign nodes that still exist up to the target size.
	for layer, nodes := range doc.Topology {
		nodeIndexes := rng.Perm(len(nodes))

		for _, idx := range nodeIndexes {
			if len(topology[layer]) >= targetNodesPerLayer {
				break
			}

			id := hash.Sum256(nodes[idx].IdentityKey)
			if n, ok := nodeMap[id]; ok {
				// There is a new descriptor with the same identity key,
				// as an existing descriptor in the previous document,
				// so preserve the layering.
				topology[layer] = append(topology[layer], n)
				delete(nodeMap, id)
			}
		}
	}

	// Flatten the map containing the nodes pending assignment.
	toAssign := make([]*pki.MixDescriptor, 0, len(nodeMap))
	for _, n := range nodeMap {
		toAssign = append(toAssign, n)
	}
	// must sort toAssign by ID!
	sortNodesByPublicKey(toAssign)

	assignIndexes := rng.Perm(len(toAssign))

	// Fill out any layers that are under the target size, by
	// randomly assigning from the pending list.
	idx := 0
	for layer := range doc.Topology {
		for len(topology[layer]) < targetNodesPerLayer {
			n := toAssign[assignIndexes[idx]]
			topology[layer] = append(topology[layer], n)
			idx++
		}
	}

	// Assign the remaining nodes.
	for layer := 0; idx < len(assignIndexes); idx++ {
		n := toAssign[assignIndexes[idx]]
		topology[layer] = append(topology[layer], n)
		layer++
		layer = layer % len(topology)
	}

	return topology
}

// generateFixedTopology returns an array of layers, which are an array of raw descriptors
// topology is represented as an array of arrays where the contents are the raw descriptors
// because a mix that does not submit a descriptor must not be in the consensus, the topology section must be populated at runtime and checked for sanity before a consensus is made
func (s *state) generateFixedTopology(nodes []*pki.MixDescriptor, srv []byte) [][]*pki.MixDescriptor {
	nodeMap := make(map[[constants.NodeIDLength]byte]*pki.MixDescriptor)
	// collect all of the identity keys from the current set of descriptors
	for _, v := range nodes {
		id := hash.Sum256(v.IdentityKey)
		nodeMap[id] = v
	}

	pkiSignatureScheme := signSchemes.ByName(s.s.cfg.Server.PKISignatureScheme)

	// range over the keys in the configuration file and collect the descriptors for each layer
	topology := make([][]*pki.MixDescriptor, len(s.s.cfg.Topology.Layers))
	for strata, layer := range s.s.cfg.Topology.Layers {
		for _, node := range layer.Nodes {

			var identityPublicKey sign.PublicKey
			var err error
			if filepath.IsAbs(node.IdentityPublicKeyPem) {
				identityPublicKey, err = signpem.FromPublicPEMFile(node.IdentityPublicKeyPem, pkiSignatureScheme)
				if err != nil {
					panic(err)
				}
			} else {
				pemFilePath := filepath.Join(s.s.cfg.Server.DataDir, node.IdentityPublicKeyPem)
				identityPublicKey, err = signpem.FromPublicPEMFile(pemFilePath, pkiSignatureScheme)
				if err != nil {
					panic(err)
				}
			}

			id := hash.Sum256From(identityPublicKey)

			// if the listed node is in the current descriptor set, place it in the layer
			if n, ok := nodeMap[id]; ok {
				topology[strata] = append(topology[strata], n)
			}
		}
	}
	return topology
}

func (s *state) generateRandomTopology(nodes []*pki.MixDescriptor, srv []byte) [][]*pki.MixDescriptor {
	s.log.Debugf("Generating random mix topology.")

	// If there is no node history in the form of a previous consensus,
	// then the simplest thing to do is to randomly assign nodes to the
	// various layers.

	if len(srv) != 32 {
		err := errors.New("SharedRandomValue too short")
		s.log.Errorf("srv: %s", srv)
		s.s.fatalErrCh <- err
	}
	rng, err := rand.NewDeterministicRandReader(srv[:])
	if err != nil {
		s.log.Errorf("DeterministicRandReader() failed to initialize: %v", err)
		s.s.fatalErrCh <- err
	}

	nodeIndexes := rng.Perm(len(nodes))
	topology := make([][]*pki.MixDescriptor, s.s.cfg.Debug.Layers)
	for idx, layer := 0, 0; idx < len(nodes); idx++ {
		n := nodes[nodeIndexes[idx]]
		topology[layer] = append(topology[layer], n)
		layer++
		layer = layer % len(topology)
	}

	return topology
}

func (s *state) pruneDocuments() {
	if s.TryLock() {
		panic("write lock not held in pruneDocuments()")
	}

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
	for e := range s.votes {
		if e < cmpEpoch {
			delete(s.votes, e)
		}
	}
	for e := range s.certificates {
		if e < cmpEpoch {
			delete(s.certificates, e)
		}
	}
	for e := range s.myconsensus {
		if e < cmpEpoch {
			delete(s.myconsensus, e)
		}
	}
}

func (s *state) isDescriptorAuthorized(desc *pki.MixDescriptor) bool {
	pk := hash.Sum256(desc.IdentityKey)
	if !desc.IsGatewayNode && !desc.IsServiceNode {
		return s.authorizedMixes[pk]
	}
	if desc.IsGatewayNode {
		name, ok := s.authorizedGatewayNodes[pk]
		if !ok {
			return false
		}
		return name == desc.Name
	}
	if desc.IsServiceNode {
		name, ok := s.authorizedServiceNodes[pk]
		if !ok {
			return false
		}
		return name == desc.Name
	}
	panic("impossible")
}

func (s *state) dupSig(sig commands.Sig) bool {
	if _, ok := s.signatures[s.votingEpoch][hash.Sum256From(sig.PublicKey)]; ok {
		return true
	}
	return false
}

func (s *state) dupVote(vote commands.Vote) bool {
	if _, ok := s.votes[s.votingEpoch][hash.Sum256From(vote.PublicKey)]; ok {
		return true
	}
	return false
}

// a certificate is a vote that has a full set of sharedrandom commit and reveals as seen by the peer
func (s *state) onCertUpload(certificate *commands.Cert) commands.Command {
	s.Lock()
	defer s.Unlock()
	resp := commands.CertStatus{}
	pk := hash.Sum256From(certificate.PublicKey)

	// if not authorized
	_, ok := s.authorizedAuthorities[pk]
	if !ok {
		s.log.Error("Voter not authorized.")
		resp.ErrorCode = commands.CertNotAuthorized
		return &resp
	}

	// XXX: this ought to use state, to prevent out-of-order protocol events, in case
	// we have any bugs in our implmementation
	if certificate.Epoch < s.votingEpoch {
		s.log.Errorf("Certificate from %s received too early: %d < %d", s.authorityNames[pk], certificate.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.CertTooEarly
		return &resp
	}
	if certificate.Epoch > s.votingEpoch {
		s.log.Errorf("Certificate from %s too late: %d > %d", s.authorityNames[pk], certificate.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.CertTooLate
		return &resp
	}

	// ensure certificate.PublicKey verifies the payload (ie Vote has a signature from this peer)
	_, err := cert.Verify(certificate.PublicKey, certificate.Payload)
	if err != nil {
		s.log.Error("Certificate from %s failed to verify.", s.authorityNames[pk])
		resp.ErrorCode = commands.CertNotSigned
		return &resp
	}

	// verify the structure of the certificate
	doc, err := s.doParseDocument(certificate.Payload)
	if err != nil {
		s.log.Error("Certficate from %s failed to verify: %s", s.authorityNames[pk], certificate.PublicKey, err)
		resp.ErrorCode = commands.CertNotSigned
		return &resp
	}

	// haven't received a vote from this peer yet for this epoch
	if _, ok := s.votes[s.votingEpoch][pk]; !ok {
		s.log.Errorf("Certficate from %s received before peer's vote?.", s.authorityNames[pk])
		resp.ErrorCode = commands.CertTooEarly
		return &resp
	}

	// the first certificate received this round
	if _, ok := s.certificates[s.votingEpoch]; !ok {
		s.certificates[s.votingEpoch] = make(map[[publicKeyHashSize]byte]*pki.Document)
	}

	// already received a certificate for this round
	if _, ok := s.certificates[s.votingEpoch][pk]; ok {
		s.log.Error("Another Cert received from peer %s", s.authorityNames[pk])
		resp.ErrorCode = commands.CertAlreadyReceived
		return &resp
	}
	s.log.Noticef("Cert OK from: %s\n%s", s.authorityNames[pk], doc)
	s.certificates[s.votingEpoch][pk] = doc
	resp.ErrorCode = commands.CertOk
	return &resp
}

func (s *state) onRevealUpload(reveal *commands.Reveal) commands.Command {
	s.Lock()
	defer s.Unlock()
	resp := commands.RevealStatus{}
	pk := hash.Sum256From(reveal.PublicKey)

	// if not authorized
	_, ok := s.authorizedAuthorities[pk]
	if !ok {
		s.log.Error("Voter not authorized.")
		resp.ErrorCode = commands.RevealNotAuthorized
		return &resp
	}

	// verify the signature on the payload
	certified, err := cert.Verify(reveal.PublicKey, reveal.Payload)
	if err != nil {
		s.log.Error("Reveal from %s failed to verify.", s.authorityNames[pk])
		resp.ErrorCode = commands.RevealNotSigned
		return &resp
	}

	e := epochFromBytes(certified[:8])
	// received too late
	if e < s.votingEpoch {
		s.log.Errorf("Reveal from %s received too late: %d < %d", s.authorityNames[pk], e, s.votingEpoch)
		resp.ErrorCode = commands.RevealTooLate
		return &resp
	}

	// received too early
	if e > s.votingEpoch {
		s.log.Errorf("Reveal from %s received too early: %d > %d", s.authorityNames[pk], e, s.votingEpoch)
		resp.ErrorCode = commands.RevealTooEarly
		return &resp
	}

	// haven't received a commit yet for this epoch
	if _, ok := s.commits[s.votingEpoch]; !ok {
		s.log.Errorf("Reveal from %s received before any commit.", s.authorityNames[pk])
		resp.ErrorCode = commands.RevealTooEarly
		return &resp
	}

	// haven't received a commit from this peer yet for this epoch
	if _, ok := s.commits[s.votingEpoch][pk]; !ok {
		s.log.Errorf("Reveal from %s received before peer's vote.", s.authorityNames[pk])
		resp.ErrorCode = commands.RevealTooEarly
		return &resp
	}

	// the first reveal received this round
	if _, ok := s.reveals[s.votingEpoch]; !ok {
		s.reveals[s.votingEpoch] = make(map[[publicKeyHashSize]byte][]byte)
	}

	// already received a reveal for this round
	if _, ok := s.reveals[s.votingEpoch][pk]; ok {
		s.log.Errorf("Reveal from %s already received", s.authorityNames[pk])
		resp.ErrorCode = commands.RevealAlreadyReceived
		return &resp
	}
	s.log.Noticef("Reveal OK from: %s\n%x", s.authorityNames[pk], certified)
	s.reveals[s.votingEpoch][pk] = reveal.Payload
	resp.ErrorCode = commands.RevealOk
	return &resp
}

func (s *state) onVoteUpload(vote *commands.Vote) commands.Command {
	s.Lock()
	defer s.Unlock()
	resp := commands.VoteStatus{}
	pk := hash.Sum256From(vote.PublicKey)

	// if not authorized
	_, ok := s.authorizedAuthorities[pk]
	if !ok {
		s.log.Error("Voter not authorized.")
		resp.ErrorCode = commands.VoteNotAuthorized
		return &resp
	}

	// XXX: this ought to use state, to prevent out-of-order protocol events, in case
	// we have any bugs in our implmementation
	if vote.Epoch < s.votingEpoch {
		s.log.Errorf("Vote from %s received too early: %d < %d", s.authorityNames[pk], vote.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.VoteTooEarly
		return &resp
	}
	if vote.Epoch > s.votingEpoch {
		s.log.Errorf("Vote from %s received too late: %d > %d", s.authorityNames[pk], vote.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.VoteTooLate
		return &resp
	}

	// haven't received a vote yet for this epoch
	if _, ok := s.votes[s.votingEpoch]; !ok {
		s.votes[s.votingEpoch] = make(map[[publicKeyHashSize]byte]*pki.Document)
	}

	// haven't received a commit yet for this epoch
	if _, ok = s.commits[s.votingEpoch]; !ok {
		s.commits[s.votingEpoch] = make(map[[publicKeyHashSize]byte][]byte)
	}

	// peer has already voted for this epoch
	_, ok = s.votes[s.votingEpoch][pk]
	if ok {
		s.log.Errorf("Vote from %s already received", s.authorityNames[pk])
		resp.ErrorCode = commands.VoteAlreadyReceived
		return &resp
	}

	// ensure vote.PublicKey verifies the payload (ie Vote has a signature from this peer)
	_, err := cert.Verify(vote.PublicKey, vote.Payload)
	if err != nil {
		s.log.Errorf("Vote from %s failed to verify.", s.authorityNames[pk])
		resp.ErrorCode = commands.VoteNotSigned
		return &resp
	}

	doc, err := s.doParseDocument(vote.Payload)
	if err != nil {
		s.log.Errorf("Vote from %s failed signature verification.", s.authorityNames[pk])
		resp.ErrorCode = commands.VoteNotSigned
		return &resp
	}

	// Check that the deserialiezd payload was signed for the correct Epoch
	if doc.Epoch != s.votingEpoch {
		s.log.Errorf("Vote from %s contains wrong Epoch %d", s.authorityNames[pk], doc.Epoch)
		resp.ErrorCode = commands.VoteMalformed
		return &resp
	}

	// extract commit from document and verify that it was signed by this peer
	// IsDocumentWellFormed has already verified that any commit is for
	// this Epoch and is signed by a known verifier
	commit, ok := doc.SharedRandomCommit[pk]
	if !ok {
		// It's possible that an authority submitted another authoritys vote on its behalf,
		// but we are not going to allow that behavior as it is not specified.
		s.log.Error("Vote from %s did not contain SharedRandom Commit.", s.authorityNames[pk])
		resp.ErrorCode = commands.VoteMalformed
		return &resp
	}
	// save the vote
	s.votes[s.votingEpoch][pk] = doc
	// save the commit
	s.commits[s.votingEpoch][pk] = commit
	s.log.Noticef("Vote OK from: %s\n%s", s.authorityNames[pk], doc)
	resp.ErrorCode = commands.VoteOk
	return &resp
}

func (s *state) onSigUpload(sig *commands.Sig) commands.Command {
	s.Lock()
	defer s.Unlock()
	resp := commands.SigStatus{}
	pk := hash.Sum256From(sig.PublicKey)

	_, ok := s.authorizedAuthorities[pk]
	if !ok {
		s.log.Error("Signature not authorized.")
		resp.ErrorCode = commands.SigNotAuthorized
		return &resp
	}
	if sig.Epoch < s.votingEpoch {
		s.log.Errorf("Signature from %s received too early: %d < %d", s.authorityNames[pk], sig.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.SigTooEarly
		return &resp
	}
	if sig.Epoch > s.votingEpoch {
		s.log.Errorf("Signature from %s received too late: %d > %d", s.authorityNames[pk], sig.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.SigTooLate
		return &resp
	}
	verified, err := cert.Verify(sig.PublicKey, sig.Payload)
	if err != nil {
		s.log.Error("Sig failed signature verification.")
		resp.ErrorCode = commands.SigNotSigned
		return &resp
	}

	// haven't received a sig yet for this epoch
	if _, ok := s.signatures[s.votingEpoch]; !ok {
		s.signatures[s.votingEpoch] = make(map[[publicKeyHashSize]byte]*cert.Signature)
	}

	// peer has not yet submitted a signature
	if !s.dupSig(*sig) {
		csig := new(cert.Signature)
		err := csig.Unmarshal(verified)
		if err != nil {
			resp.ErrorCode = commands.SigInvalid
			s.log.Errorf("Signature failed to deserialize from: %s", s.authorityNames[pk])
			return &resp
		}
		s.log.Noticef("Signature OK from: %s", s.authorityNames[pk])
		s.signatures[s.votingEpoch][hash.Sum256From(sig.PublicKey)] = csig
		resp.ErrorCode = commands.SigOk
		return &resp
	} else {
		// peer is behaving strangely
		// error; two sigs from same peer
		s.log.Error("Sig command invalid: more than one sig from same peer is not allowed.")
		resp.ErrorCode = commands.SigAlreadyReceived
		return &resp
	}
}

func (s *state) onDescriptorUpload(rawDesc []byte, desc *pki.MixDescriptor, epoch uint64) error {
	s.Lock()
	defer s.Unlock()

	// Note: Caller ensures that the epoch is the current epoch +- 1.
	pk := hash.Sum256(desc.IdentityKey)

	// Get the public key -> descriptor map for the epoch.
	_, ok := s.descriptors[epoch]
	if !ok {
		s.descriptors[epoch] = make(map[[publicKeyHashSize]byte]*pki.MixDescriptor)
	}

	// Check for redundant uploads.
	d, ok := s.descriptors[epoch][pk]
	if ok {
		// If the descriptor changes, then it will be rejected to prevent
		// nodes from reneging on uploads.
		serialized, err := d.MarshalBinary()
		if err != nil {
			return err
		}
		if !hmac.Equal(serialized, rawDesc) {
			return fmt.Errorf("state: node %s (%x): Conflicting descriptor for epoch %v", desc.Name, hash.Sum256(desc.IdentityKey), epoch)
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
		return eBkt.Put(pk[:], rawDesc)
	}); err != nil {
		// Persistence failures are FATAL.
		s.s.fatalErrCh <- err
	}

	// Store the parsed descriptor
	s.descriptors[epoch][pk] = desc

	s.log.Noticef("Node %x: Successfully submitted descriptor for epoch %v.", pk, epoch)
	s.onUpdate()
	return nil
}

func (s *state) documentForEpoch(epoch uint64) ([]byte, error) {
	var generationDeadline = 7 * (epochtime.Period / 8)

	s.RLock()
	defer s.RUnlock()

	// If we have a serialized document, return it.
	if d, ok := s.documents[epoch]; ok {
		// XXX We should cache this
		return d.MarshalBinary()
	}

	// Otherwise, return an error based on the time.
	now, elapsed, _ := epochtime.Now()
	switch epoch {
	case now:
		// We missed the deadline to publish a descriptor for the current
		// epoch, so we will never be able to service this request.
		s.log.Errorf("No document for current epoch %v generated and never will be", now)
		return nil, errGone
	case now + 1:
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
				epochBytes := epochToBytes(epoch)
				if rawDoc := docsBkt.Get(epochBytes); rawDoc != nil {
					_, _, _, err := cert.VerifyThreshold(s.getVerifiers(), s.threshold, rawDoc)
					if err != nil {
						s.log.Errorf("Failed to verify threshold on restored document")
						break // or continue?
					}
					doc, err := s.doParseDocument(rawDoc)
					if err != nil {
						s.log.Errorf("Failed to validate persisted document: %v", err)
					} else if doc.Epoch != epoch {
						// The document for the wrong epoch was persisted?
						s.log.Errorf("Persisted document has unexpected epoch: %v", doc.Epoch)
					} else {
						s.log.Debugf("Restored Document for epoch %v: %v.", epoch, doc)
						s.documents[epoch] = doc
					}
				}

				eDescsBkt := descsBkt.Bucket(epochBytes)
				if eDescsBkt == nil {
					s.log.Debugf("No persisted Descriptors for epoch: %v.", epoch)
					continue
				}

				c := eDescsBkt.Cursor()
				for wantHash, rawDesc := c.First(); wantHash != nil; wantHash, rawDesc = c.Next() {
					if len(wantHash) != publicKeyHashSize {
						panic("stored hash should be 32 bytes")
					}
					desc := new(pki.MixDescriptor)
					err := desc.UnmarshalBinary(rawDesc)
					if err != nil {
						s.log.Errorf("Failed to validate persisted descriptor: %v", err)
						continue
					}
					idHash := hash.Sum256(desc.IdentityKey)
					if !hmac.Equal(wantHash, idHash[:]) {
						s.log.Errorf("Discarding persisted descriptor: key mismatch")
						continue
					}

					if !s.isDescriptorAuthorized(desc) {
						s.log.Warningf("Discarding persisted descriptor: %v", desc)
						continue
					}

					_, ok := s.descriptors[epoch]
					if !ok {
						s.descriptors[epoch] = make(map[[publicKeyHashSize]byte]*pki.MixDescriptor)
					}

					s.descriptors[epoch][hash.Sum256(desc.IdentityKey)] = desc
					s.log.Debugf("Restored descriptor for epoch %v: %+v", epoch, desc)
				}
			}
			return nil
		}

		// We created a new database, so populate the new `metadata` bucket.
		return bkt.Put([]byte(versionKey), []byte{0})
	})
}

func newState(s *Server) (*state, error) {
	const dbFile = "persistence.db"

	st := new(state)
	st.s = s
	st.geo = s.geo
	st.log = s.logBackend.GetLogger("state")

	// set voting schedule at runtime

	st.log.Debugf("State initialized with epoch Period: %s", epochtime.Period)
	st.log.Debugf("State initialized with MixPublishDeadline: %s", MixPublishDeadline)
	st.log.Debugf("State initialized with AuthorityVoteDeadline: %s", AuthorityVoteDeadline)
	st.log.Debugf("State initialized with AuthorityRevealDeadline: %s", AuthorityRevealDeadline)
	st.log.Debugf("State initialized with PublishConsensusDeadline: %s", PublishConsensusDeadline)
	st.verifiers = make(map[[publicKeyHashSize]byte]sign.PublicKey)
	for _, auth := range s.cfg.Authorities {
		st.verifiers[hash.Sum256From(auth.IdentityPublicKey)] = auth.IdentityPublicKey
	}
	st.verifiers[hash.Sum256From(s.IdentityKey())] = sign.PublicKey(s.IdentityKey())
	st.threshold = len(st.verifiers)/2 + 1
	st.dissenters = len(s.cfg.Authorities)/2 - 1

	st.s.cfg.Server.PKISignatureScheme = s.cfg.Server.PKISignatureScheme
	pkiSignatureScheme := signSchemes.ByName(s.cfg.Server.PKISignatureScheme)

	// Initialize the authorized peer tables.
	st.reverseHash = make(map[[publicKeyHashSize]byte]sign.PublicKey)
	st.authorizedMixes = make(map[[publicKeyHashSize]byte]bool)
	for _, v := range st.s.cfg.Mixes {
		var identityPublicKey sign.PublicKey
		var err error
		if filepath.IsAbs(v.IdentityPublicKeyPem) {
			identityPublicKey, err = signpem.FromPublicPEMFile(v.IdentityPublicKeyPem, pkiSignatureScheme)
			if err != nil {
				panic(err)
			}
		} else {
			pemFilePath := filepath.Join(s.cfg.Server.DataDir, v.IdentityPublicKeyPem)
			identityPublicKey, err = signpem.FromPublicPEMFile(pemFilePath, pkiSignatureScheme)
			if err != nil {
				panic(err)
			}
		}

		pk := hash.Sum256From(identityPublicKey)
		st.authorizedMixes[pk] = true
		st.reverseHash[pk] = identityPublicKey
	}
	st.authorizedGatewayNodes = make(map[[publicKeyHashSize]byte]string)
	for _, v := range st.s.cfg.GatewayNodes {
		var identityPublicKey sign.PublicKey
		var err error

		if filepath.IsAbs(v.IdentityPublicKeyPem) {
			identityPublicKey, err = signpem.FromPublicPEMFile(v.IdentityPublicKeyPem, pkiSignatureScheme)
			if err != nil {
				panic(err)
			}
		} else {
			pemFilePath := filepath.Join(s.cfg.Server.DataDir, v.IdentityPublicKeyPem)
			identityPublicKey, err = signpem.FromPublicPEMFile(pemFilePath, pkiSignatureScheme)
			if err != nil {
				panic(err)
			}
		}

		pk := hash.Sum256From(identityPublicKey)
		st.authorizedGatewayNodes[pk] = v.Identifier
		st.reverseHash[pk] = identityPublicKey
	}
	st.authorizedServiceNodes = make(map[[publicKeyHashSize]byte]string)
	for _, v := range st.s.cfg.ServiceNodes {
		var identityPublicKey sign.PublicKey
		var err error

		if filepath.IsAbs(v.IdentityPublicKeyPem) {
			identityPublicKey, err = signpem.FromPublicPEMFile(v.IdentityPublicKeyPem, pkiSignatureScheme)
			if err != nil {
				panic(err)
			}
		} else {
			pemFilePath := filepath.Join(s.cfg.Server.DataDir, v.IdentityPublicKeyPem)
			identityPublicKey, err = signpem.FromPublicPEMFile(pemFilePath, pkiSignatureScheme)
			if err != nil {
				panic(err)
			}
		}

		pk := hash.Sum256From(identityPublicKey)
		st.authorizedServiceNodes[pk] = v.Identifier
		st.reverseHash[pk] = identityPublicKey
	}
	st.authorizedAuthorities = make(map[[publicKeyHashSize]byte]bool)
	st.authorityLinkKeys = make(map[[publicKeyHashSize]byte]kem.PublicKey)
	st.authorityNames = make(map[[publicKeyHashSize]byte]string)
	for _, v := range st.s.cfg.Authorities {
		pk := hash.Sum256From(v.IdentityPublicKey)
		st.authorizedAuthorities[pk] = true
		st.authorityLinkKeys[pk] = v.LinkPublicKey
		st.reverseHash[pk] = v.IdentityPublicKey
		st.authorityNames[pk] = v.Identifier
	}
	st.reverseHash[hash.Sum256From(st.s.identityPublicKey)] = st.s.identityPublicKey

	st.documents = make(map[uint64]*pki.Document)
	st.myconsensus = make(map[uint64]*pki.Document)
	st.descriptors = make(map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor)
	st.votes = make(map[uint64]map[[publicKeyHashSize]byte]*pki.Document)
	st.certificates = make(map[uint64]map[[publicKeyHashSize]byte]*pki.Document)
	st.reveals = make(map[uint64]map[[publicKeyHashSize]byte][]byte)
	st.signatures = make(map[uint64]map[[publicKeyHashSize]byte]*cert.Signature)
	st.commits = make(map[uint64]map[[publicKeyHashSize]byte][]byte)
	st.priorSRV = make([][]byte, 0)

	// Initialize the persistence store and restore state.
	dbPath := filepath.Join(s.cfg.Server.DataDir, dbFile)
	var err error
	if st.db, err = bolt.Open(dbPath, 0600, nil); err != nil {
		return nil, err
	}
	if err = st.restorePersistence(); err != nil {
		st.db.Close()
		return nil, err
	}

	// Set the initial state to bootstrap
	st.state = stateBootstrap
	return st, nil
}

func (s *state) backgroundFetchConsensus(epoch uint64) {
	if s.TryLock() {
		panic("write lock not held in backgroundFetchConsensus(epoch)")
	}

	// If there isn't a consensus for the previous epoch, ask the other
	// authorities for a consensus.
	_, ok := s.documents[epoch]
	if !ok {
		kemscheme := schemes.ByName(s.s.cfg.Server.WireKEMScheme)
		if kemscheme == nil {
			panic("kem scheme not found in registry")
		}
		pkiSignatureScheme := signSchemes.ByName(s.s.cfg.Server.PKISignatureScheme)
		if pkiSignatureScheme == nil {
			panic("pki signature scheme not found in registry")
		}
		go func() {
			cfg := &client.Config{
				KEMScheme:          kemscheme,
				PKISignatureScheme: pkiSignatureScheme,
				LinkKey:            s.s.linkKey,
				LogBackend:         s.s.logBackend,
				Authorities:        s.s.cfg.Authorities,
				DialContextFn:      nil,
				Geo:                s.geo,
			}
			c, err := client.New(cfg)
			if err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute*2)
			defer cancel()
			doc, _, err := c.Get(ctx, epoch)
			if err != nil {
				return
			}
			s.Lock()
			defer s.Unlock()

			// It's possible that the state has changed
			// if backgroundFetchConsensus was called
			// multiple times during bootstrapping
			if _, ok := s.documents[epoch]; !ok {
				s.documents[epoch] = doc
			}
		}()
	}
}

func epochToBytes(e uint64) []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, e)
	return ret
}

func epochFromBytes(b []byte) uint64 {
	return binary.BigEndian.Uint64(b[0:8])
}

func sortNodesByPublicKey(nodes []*pki.MixDescriptor) {
	dTos := func(d *pki.MixDescriptor) string {
		pk := hash.Sum256(d.IdentityKey)
		return string(pk[:])
	}
	sort.Slice(nodes, func(i, j int) bool { return dTos(nodes[i]) < dTos(nodes[j]) })
}

func sha256b64(raw []byte) string {
	hash := blake2b.Sum256(raw)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// validate the topology
func (s *state) verifyTopology(topology [][]*pki.MixDescriptor) error {
	if len(topology) < s.s.cfg.Debug.Layers {
		return errInvalidTopology
	}

	for strata, _ := range topology {
		if len(topology[strata]) < s.s.cfg.Debug.MinNodesPerLayer {
			return errInvalidTopology
		}
	}
	return nil
}

// generate commit and reveal values and save them
func (s *state) doCommit(epoch uint64) ([]byte, error) {
	s.log.Debugf("Generating SharedRandom Commit for %d", epoch)
	srv := new(pki.SharedRandom)
	commit, err := srv.Commit(epoch)
	if err != nil {
		return nil, err
	}
	// sign the serialized commit
	signedCommit, err := cert.Sign(s.s.identityPrivateKey, s.s.identityPublicKey, commit, epoch)
	if err != nil {
		return nil, err
	}
	// sign the reveal
	signedReveal, err := cert.Sign(s.s.identityPrivateKey, s.s.identityPublicKey, srv.Reveal(), epoch)
	if err != nil {
		return nil, err
	}
	// save our commit
	if _, ok := s.commits[epoch]; !ok {
		s.commits[epoch] = make(map[[pki.PublicKeyHashSize]byte][]byte)
	}
	s.commits[epoch][s.identityPubKeyHash()] = signedCommit

	// save our reveal
	if _, ok := s.reveals[epoch]; !ok {
		s.reveals[epoch] = make(map[[pki.PublicKeyHashSize]byte][]byte)
	}
	s.reveals[epoch][s.identityPubKeyHash()] = signedReveal
	return signedCommit, nil
}

func (s *state) reveal(epoch uint64) []byte {
	signed, ok := s.reveals[epoch][s.identityPubKeyHash()]
	if !ok {
		s.s.fatalErrCh <- errors.New("reveal() called without commit")
	}
	return signed
}
