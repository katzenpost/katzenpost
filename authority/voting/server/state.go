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
	"net/url"
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
	"github.com/katzenpost/katzenpost/quic/common"
)

const (
	descriptorsBucket        = "descriptors"
	replicaDescriptorsBucket = "replica_descriptors"
	documentsBucket          = "documents"
	stateAcceptDescriptor    = "accept_desc"
	stateAcceptVote          = "accept_vote"
	stateAcceptReveal        = "accept_reveal"
	stateAcceptCert          = "accept_cert"
	stateAcceptSignature     = "accept_signature"
	stateBootstrap           = "bootstrap"

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
	authorizedReplicaNodes map[[publicKeyHashSize]byte]string
	authorizedAuthorities  map[[publicKeyHashSize]byte]bool
	authorityLinkKeys      map[[publicKeyHashSize]byte]kem.PublicKey
	authorityNames         map[[publicKeyHashSize]byte]string

	documents          map[uint64]*pki.Document
	myconsensus        map[uint64]*pki.Document
	descriptors        map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor
	replicaDescriptors map[uint64]map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor
	votes              map[uint64]map[[publicKeyHashSize]byte]*pki.Document
	certificates       map[uint64]map[[publicKeyHashSize]byte]*pki.Document
	signatures         map[uint64]map[[publicKeyHashSize]byte]*cert.Signature
	priorSRV           [][]byte
	reveals            map[uint64]map[[publicKeyHashSize]byte][]byte
	commits            map[uint64]map[[publicKeyHashSize]byte][]byte
	verifiers          map[[publicKeyHashSize]byte]sign.PublicKey

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
	s.log.Debugf("FSM: Current epoch %d, elapsed: %s, remaining time: %s, current state: %s", epoch, elapsed, nextEpoch, s.state)

	switch s.state {
	case stateBootstrap:
		s.log.Noticef("FSM: Entering bootstrap state for epoch %d", epoch)
		s.genesisEpoch = 0
		s.log.Debugf("FSM: Fetching consensus for previous epoch %d", epoch-1)
		s.backgroundFetchConsensus(epoch - 1)
		s.log.Debugf("FSM: Fetching consensus for current epoch %d", epoch)
		s.backgroundFetchConsensus(epoch)
		if elapsed > MixPublishDeadline {
			s.log.Errorf("FSM: Too late to vote this round (elapsed %s > deadline %s), sleeping until next epoch %s", elapsed, MixPublishDeadline, nextEpoch)
			sleep = nextEpoch
			s.votingEpoch = epoch + 2
			s.state = stateBootstrap
			s.log.Warningf("FSM: Staying in bootstrap state, will vote for epoch %d", s.votingEpoch)
		} else {
			s.votingEpoch = epoch + 1
			s.state = stateAcceptDescriptor
			sleep = MixPublishDeadline - elapsed
			if sleep < 0 {
				sleep = 0
			}
			s.log.Noticef("FSM: Bootstrapping complete, transitioning to %s state for voting epoch %d, sleeping for %s", s.state, s.votingEpoch, sleep)
		}
	case stateAcceptDescriptor:
		s.log.Noticef("FSM: Entering stateAcceptDescriptor for epoch %d", s.votingEpoch)
		descriptorCount := 0
		if descs, ok := s.descriptors[s.votingEpoch]; ok {
			descriptorCount = len(descs)
		}
		s.log.Debugf("FSM: Currently have %d descriptors for epoch %d", descriptorCount, s.votingEpoch)

		// Check if we already have our own vote/commit stored
		if votes, ok := s.votes[s.votingEpoch]; ok {
			if _, hasOurVote := votes[s.identityPubKeyHash()]; hasOurVote {
				s.log.Debugf("FSM: Already have our own vote stored for epoch %d", s.votingEpoch)
			}
		}
		if commits, ok := s.commits[s.votingEpoch]; ok {
			if _, hasOurCommit := commits[s.identityPubKeyHash()]; hasOurCommit {
				s.log.Debugf("FSM: Already have our own commit stored for epoch %d", s.votingEpoch)
			}
		}

		s.log.Debugf("FSM: Generating vote for epoch %d", s.votingEpoch)
		signed, err := s.getVote(s.votingEpoch)
		if err == nil {
			s.log.Noticef("FSM: Successfully generated vote for epoch %d", s.votingEpoch)

			// Verify our vote and commit were stored
			if votes, ok := s.votes[s.votingEpoch]; ok {
				if _, hasOurVote := votes[s.identityPubKeyHash()]; hasOurVote {
					s.log.Debugf("FSM: Confirmed our vote is stored for epoch %d", s.votingEpoch)
				} else {
					s.log.Errorf("FSM: CRITICAL - our vote was NOT stored for epoch %d", s.votingEpoch)
				}
			} else {
				s.log.Errorf("FSM: CRITICAL - no votes map exists for epoch %d", s.votingEpoch)
			}

			if commits, ok := s.commits[s.votingEpoch]; ok {
				if _, hasOurCommit := commits[s.identityPubKeyHash()]; hasOurCommit {
					s.log.Debugf("FSM: Confirmed our commit is stored for epoch %d", s.votingEpoch)
				} else {
					s.log.Errorf("FSM: CRITICAL - our commit was NOT stored for epoch %d", s.votingEpoch)
				}
			} else {
				s.log.Errorf("FSM: CRITICAL - no commits map exists for epoch %d", s.votingEpoch)
			}

			serialized, err := signed.MarshalCertificate()
			if err == nil {
				s.log.Debugf("FSM: Successfully serialized vote certificate for epoch %d", s.votingEpoch)
				s.sendVoteToAuthorities(serialized, s.votingEpoch)
			} else {
				s.log.Errorf("FSM: Failed to serialize certificate for epoch %v: %s", s.votingEpoch, err)
			}
		} else {
			s.log.Errorf("FSM: Failed to compute vote for epoch %v: %s", s.votingEpoch, err)
		}
		s.state = stateAcceptVote
		_, nowelapsed, _ := epochtime.Now()
		sleep = AuthorityVoteDeadline - nowelapsed
		s.log.Noticef("FSM: Transitioning to %s state, sleeping for %s until vote deadline", s.state, sleep)
	case stateAcceptVote:
		s.log.Noticef("FSM: Entering stateAcceptVote for epoch %d", s.votingEpoch)
		voteCount := 0
		if votes, ok := s.votes[s.votingEpoch]; ok {
			voteCount = len(votes)
		}
		s.log.Debugf("FSM: Currently have %d votes for epoch %d (threshold: %d)", voteCount, s.votingEpoch, s.threshold)

		signed := s.reveal(s.votingEpoch)
		s.log.Debugf("FSM: Generated reveal for epoch %d", s.votingEpoch)
		s.sendRevealToAuthorities(signed, s.votingEpoch)
		s.state = stateAcceptReveal
		_, nowelapsed, _ := epochtime.Now()
		sleep = AuthorityRevealDeadline - nowelapsed
		s.log.Noticef("FSM: Transitioning to %s state, sleeping for %s until reveal deadline", s.state, sleep)
	case stateAcceptReveal:
		s.log.Noticef("FSM: Entering stateAcceptReveal for epoch %d", s.votingEpoch)
		revealCount := 0
		if reveals, ok := s.reveals[s.votingEpoch]; ok {
			revealCount = len(reveals)
		}
		s.log.Debugf("FSM: Currently have %d reveals for epoch %d (threshold: %d)", revealCount, s.votingEpoch, s.threshold)

		signed, err := s.getCertificate(s.votingEpoch)
		if err == nil {
			s.log.Noticef("FSM: Successfully generated certificate for epoch %d", s.votingEpoch)
			serialized, err := signed.MarshalCertificate()
			if err == nil {
				s.log.Debugf("FSM: Successfully serialized certificate for epoch %d", s.votingEpoch)
				s.sendCertToAuthorities(serialized, s.votingEpoch)
			} else {
				s.log.Errorf("FSM: Failed to serialize certificate for epoch %v: %s", s.votingEpoch, err)
			}
		} else {
			s.log.Errorf("FSM: Failed to compute certificate for epoch %v: %s", s.votingEpoch, err)
		}
		s.state = stateAcceptCert
		_, nowelapsed, _ := epochtime.Now()
		sleep = AuthorityCertDeadline - nowelapsed
		s.log.Noticef("FSM: Transitioning to %s state, sleeping for %s until cert deadline", s.state, sleep)
	case stateAcceptCert:
		s.log.Noticef("FSM: Entering stateAcceptCert for epoch %d", s.votingEpoch)
		certCount := 0
		if certs, ok := s.certificates[s.votingEpoch]; ok {
			certCount = len(certs)
		}
		s.log.Debugf("FSM: Currently have %d certificates for epoch %d (threshold: %d)", certCount, s.votingEpoch, s.threshold)

		doc, err := s.getMyConsensus(s.votingEpoch)
		if err == nil {
			s.log.Noticef("FSM: Successfully computed my view of consensus for epoch %d: %x\n%s", s.votingEpoch, s.identityPubKeyHash(), doc)
			// detach signature and send to authorities
			sig, ok := doc.Signatures[s.identityPubKeyHash()]
			if !ok {
				fatalErr := fmt.Errorf("FSM FATAL: Failed to find our signature for epoch %v in consensus document - this indicates a critical consensus building failure", s.votingEpoch)
				s.log.Errorf("FSM: %v", fatalErr)
				s.s.fatalErrCh <- fatalErr
				break
			}
			s.log.Debugf("FSM: Found our signature in consensus document for epoch %d", s.votingEpoch)
			serialized, err := sig.Marshal()
			if err != nil {
				fatalErr := fmt.Errorf("FSM FATAL: Failed to serialize our signature for epoch %v: %s - this indicates a critical cryptographic failure", s.votingEpoch, err)
				s.log.Errorf("FSM: %v", fatalErr)
				s.s.fatalErrCh <- fatalErr
				break
			}
			s.log.Debugf("FSM: Successfully serialized our signature for epoch %d", s.votingEpoch)
			signed, err := cert.Sign(s.s.identityPrivateKey, s.s.identityPublicKey, serialized, s.votingEpoch)
			if err != nil {
				s.log.Errorf("FSM: Failed to sign our signature for epoch %v: %s", s.votingEpoch, err)
				s.s.fatalErrCh <- err
				break
			}
			s.log.Debugf("FSM: Successfully signed our signature for epoch %d", s.votingEpoch)
			s.sendSigToAuthorities(signed, s.votingEpoch)
		} else {
			s.log.Errorf("FSM: Failed to compute our view of consensus for epoch %v: %s", s.votingEpoch, err)
		}
		s.state = stateAcceptSignature
		_, nowelapsed, _ := epochtime.Now()
		sleep = PublishConsensusDeadline - nowelapsed
		s.log.Noticef("FSM: Transitioning to %s state, sleeping for %s until consensus deadline", s.state, sleep)
	case stateAcceptSignature:
		s.log.Noticef("FSM: Entering stateAcceptSignature for epoch %d", s.votingEpoch)
		sigCount := 0
		if sigs, ok := s.signatures[s.votingEpoch]; ok {
			sigCount = len(sigs)
		}
		s.log.Debugf("FSM: Currently have %d signatures for epoch %d (threshold: %d)", sigCount, s.votingEpoch, s.threshold)

		// combine signatures over a certificate and see if we make a threshold consensus
		s.log.Noticef("FSM: Attempting to combine signatures for threshold consensus for epoch %v", s.votingEpoch)
		consensus, err := s.getThresholdConsensus(s.votingEpoch)
		_, _, nextEpoch := epochtime.Now()
		if err == nil {
			s.log.Noticef("FSM: SUCCESS! Achieved threshold consensus for epoch %d: %v", s.votingEpoch, consensus)
			s.state = stateAcceptDescriptor
			sleep = MixPublishDeadline + nextEpoch
			s.votingEpoch++
			s.log.Noticef("FSM: Consensus successful, transitioning to %s state for next voting epoch %d, sleeping for %s", s.state, s.votingEpoch, sleep)
		} else {
			s.log.Errorf("FSM: CONSENSUS FAILURE for epoch %d: %s", s.votingEpoch, err)
			s.log.Errorf("FSM: Had %d signatures out of %d required threshold", sigCount, s.threshold)
			s.state = stateBootstrap
			s.votingEpoch = epoch + 2 // vote on epoch+2 in epoch+1
			sleep = nextEpoch
			s.log.Errorf("FSM: Consensus failed, transitioning to %s state, will vote for epoch %d, sleeping for %s", s.state, s.votingEpoch, sleep)
		}
	default:
		s.log.Errorf("FSM: Unknown state: %s", s.state)
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
		fatalErr := fmt.Errorf("PERSISTENCE FATAL: Failed to persist consensus document for epoch %d to database: %v - this indicates critical storage failure", epoch, err)
		s.log.Errorf("persistDocument: %v", fatalErr)
		s.s.fatalErrCh <- fatalErr
	}
}

// getVote produces a pki.Document using all MixDescriptors that we have seen
func (s *state) getVote(epoch uint64) (*pki.Document, error) {
	s.log.Debugf("getVote: Generating vote for epoch %d", epoch)

	// Is there a prior consensus? If so, obtain the GenesisEpoch and prior SRV values
	if d, ok := s.documents[s.votingEpoch-1]; ok {
		s.log.Debugf("getVote: Restoring genesisEpoch %d from document cache for epoch %d", d.GenesisEpoch, s.votingEpoch-1)
		s.genesisEpoch = d.GenesisEpoch
		s.priorSRV = d.PriorSharedRandom
		d.PKISignatureScheme = s.s.cfg.Server.PKISignatureScheme
		s.log.Debugf("getVote: Using prior SRV values from previous consensus")
	} else {
		s.log.Debugf("getVote: No prior consensus found, setting genesisEpoch %d from votingEpoch", s.votingEpoch)
		s.genesisEpoch = s.votingEpoch
	}

	descriptors := []*pki.MixDescriptor{}
	if descs, ok := s.descriptors[epoch]; ok {
		for _, desc := range descs {
			descriptors = append(descriptors, desc)
		}
		s.log.Debugf("getVote: Collected %d mix descriptors for epoch %d", len(descriptors), epoch)
	} else {
		s.log.Warningf("getVote: No mix descriptors found for epoch %d", epoch)
	}

	replicaDescriptors := []*pki.ReplicaDescriptor{}
	if repDescs, ok := s.replicaDescriptors[epoch]; ok {
		for _, desc := range repDescs {
			replicaDescriptors = append(replicaDescriptors, desc)
		}
		s.log.Debugf("getVote: Collected %d replica descriptors for epoch %d", len(replicaDescriptors), epoch)
	} else {
		s.log.Debugf("getVote: No replica descriptors found for epoch %d", epoch)
	}

	// Check if we have enough descriptors to make a meaningful vote
	if !s.hasEnoughDescriptors(s.descriptors[epoch]) {
		s.log.Errorf("getVote: Insufficient descriptors for epoch %d to generate meaningful vote", epoch)
		return nil, fmt.Errorf("insufficient descriptors for epoch %d", epoch)
	}

	// vote topology is irrelevent.
	var zeros [32]byte
	s.log.Debugf("getVote: Generating document with %d mix descriptors and %d replica descriptors", len(descriptors), len(replicaDescriptors))
	vote := s.getDocument(descriptors, replicaDescriptors, s.s.cfg.Parameters, zeros[:])

	// create our SharedRandom Commit
	s.log.Debugf("getVote: Generating SharedRandom commit for epoch %d", epoch)
	signedCommit, err := s.doCommit(epoch)
	if err != nil {
		s.log.Errorf("getVote: Failed to generate SharedRandom commit for epoch %d: %s", epoch, err)
		return nil, err
	}
	commits := make(map[[hash.HashSize]byte][]byte)
	commits[s.identityPubKeyHash()] = signedCommit
	vote.SharedRandomCommit = commits
	s.log.Debugf("getVote: Added SharedRandom commit to vote for epoch %d", epoch)

	s.log.Debugf("getVote: Signing vote document for epoch %d", epoch)
	_, err = s.doSignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, vote)
	if err != nil {
		s.log.Errorf("getVote: Failed to sign vote document for epoch %d: %s", epoch, err)
		return nil, err
	}

	s.log.Debugf("getVote: Ready to send our vote for epoch %d:\n%s", epoch, vote)
	// save our own vote
	if _, ok := s.votes[epoch]; !ok {
		s.votes[epoch] = make(map[[publicKeyHashSize]byte]*pki.Document)
	}
	if _, ok := s.votes[epoch][s.identityPubKeyHash()]; !ok {
		s.votes[epoch][s.identityPubKeyHash()] = vote
		s.log.Debugf("getVote: Successfully saved our vote for epoch %d", epoch)
	} else {
		s.log.Errorf("getVote: Vote already present for epoch %d, this should never happen", epoch)
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

	mixes, replicas, params, err := s.tallyVotes(epoch)
	if err != nil {
		s.log.Warningf("No document for epoch %v, aborting!, %v", epoch, err)
		return nil, err
	}
	s.log.Debug("Mixes tallied, now making a document")
	var zeros [32]byte
	srv := zeros[:]
	certificate := s.getDocument(mixes, replicas, params, srv)
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

	s.log.Debugf("getMyConsensus: Computing consensus for epoch %d", epoch)

	certificates, ok := s.certificates[epoch]
	if !ok {
		s.log.Errorf("getMyConsensus: No certificates found for epoch %d", epoch)
		return nil, fmt.Errorf("no certificates for epoch %d", epoch)
	}
	s.log.Debugf("getMyConsensus: Found %d certificates for epoch %d", len(certificates), epoch)

	// well this isn't going to work then is it?
	if len(certificates) < s.threshold {
		s.log.Errorf("getMyConsensus: Insufficient certificates for consensus: have %d, need %d for epoch %d", len(certificates), s.threshold, epoch)
		return nil, fmt.Errorf("no way to make consensus with too few votes!, only %d certificates", len(certificates))
	}
	s.log.Debugf("getMyConsensus: Have sufficient certificates (%d >= %d) for epoch %d", len(certificates), s.threshold, epoch)

	// verify that all shared random commit and reveal are present for this epoch
	s.log.Debugf("getMyConsensus: Verifying SharedRandom commits and reveals for epoch %d", epoch)
	commits, reveals := s.verifyCommits(epoch)
	if len(commits) < s.threshold {
		s.log.Errorf("getMyConsensus: Insufficient SharedRandom commits for consensus: have %d, need %d for epoch %d", len(commits), s.threshold, epoch)
		return nil, fmt.Errorf("no way to make consensus with too few SharedRandom commits!, only %d commits", len(commits))
	}
	if len(commits) != len(reveals) {
		s.log.Errorf("getMyConsensus: Mismatch between commits (%d) and reveals (%d) for epoch %d", len(commits), len(reveals), epoch)
		panic("ShouldNotBePossible")
	}
	s.log.Debugf("getMyConsensus: Have sufficient SharedRandom commits (%d) and reveals (%d) for epoch %d", len(commits), len(reveals), epoch)

	// compute the shared random for the consensus
	s.log.Debugf("getMyConsensus: Computing SharedRandom value for epoch %d", epoch)
	srv, err := s.computeSharedRandom(epoch, commits, reveals)
	if err != nil {
		s.log.Errorf("getMyConsensus: Failed to compute SharedRandom for epoch %d: %s", epoch, err)
		return nil, err
	}
	s.log.Debugf("getMyConsensus: Successfully computed SharedRandom value for epoch %d: %x", epoch, srv)

	// if there are no prior SRV values, copy the current srv twice
	if epoch == s.genesisEpoch {
		s.priorSRV = [][]byte{srv, srv}
		s.log.Debugf("getMyConsensus: Genesis epoch %d, initializing priorSRV with current SRV", epoch)
	} else if epoch%epochtime.WeekOfEpochs == 0 {
		// rotate the weekly epochs if it is time to do so.
		s.priorSRV = [][]byte{srv, s.priorSRV[0]}
		s.log.Debugf("getMyConsensus: Weekly epoch rotation for epoch %d", epoch)
	}

	s.log.Debugf("getMyConsensus: Tallying votes for epoch %d", epoch)
	mixes, replicas, params, err := s.tallyVotes(epoch)
	if err != nil {
		s.log.Errorf("getMyConsensus: Failed to tally votes for epoch %d: %s", epoch, err)
		return nil, err
	}
	s.log.Debugf("getMyConsensus: Successfully tallied votes: %d mixes, %d replicas for epoch %d", len(mixes), len(replicas), epoch)

	s.log.Debugf("getMyConsensus: Generating consensus document for epoch %d", epoch)
	consensusOfOne := s.getDocument(mixes, replicas, params, srv)

	s.log.Debugf("getMyConsensus: Signing consensus document for epoch %d", epoch)
	_, err = s.doSignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, consensusOfOne)
	if err != nil {
		s.log.Errorf("getMyConsensus: Failed to sign consensus document for epoch %d: %s", epoch, err)
		return nil, err
	}

	// save our view of the conseusus
	s.myconsensus[epoch] = consensusOfOne
	s.log.Noticef("getMyConsensus: Successfully computed and saved consensus for epoch %d", epoch)
	return consensusOfOne, nil
}

// getThresholdConsensus returns a *pki.Document iff a threshold consensus is reached or error
func (s *state) getThresholdConsensus(epoch uint64) (*pki.Document, error) {
	// range over the certificates we have collected and see if we can collect enough signatures to make a consensus
	if s.TryLock() {
		panic("write lock not held in getThresholdConsensus(epoch)")
	}

	s.log.Debugf("getThresholdConsensus: Attempting to reach threshold consensus for epoch %d", epoch)

	ourConsensus, ok := s.myconsensus[epoch]
	if !ok {
		s.log.Errorf("getThresholdConsensus: No consensus view available for epoch %d", epoch)
		return nil, fmt.Errorf("we have no view of consensus!")
	}
	s.log.Debugf("getThresholdConsensus: Found our consensus view for epoch %d", epoch)

	sigCount := 0
	if sigs, ok := s.signatures[epoch]; ok {
		sigCount = len(sigs)
	}
	s.log.Debugf("getThresholdConsensus: Processing %d signatures for epoch %d (threshold: %d)", sigCount, epoch, s.threshold)

	successfulSigs := 0
	failedSigs := 0
	for pk, signature := range s.signatures[epoch] {
		authorityName := s.authorityNames[pk]
		s.log.Debugf("getThresholdConsensus: Processing signature from authority %s (%x) for epoch %d", authorityName, pk, epoch)
		v := s.reverseHash[pk]
		err := ourConsensus.AddSignature(v, *signature)
		if err != nil {
			s.log.Errorf("getThresholdConsensus: Failed to add signature from authority %s (%x) to consensus for epoch %d: %s", authorityName, pk, epoch, err)
			failedSigs++
		} else {
			s.log.Debugf("getThresholdConsensus: Successfully added signature from authority %s (%x) to consensus for epoch %d", authorityName, pk, epoch)
			successfulSigs++
		}
	}
	s.log.Debugf("getThresholdConsensus: Signature processing complete for epoch %d: %d successful, %d failed", epoch, successfulSigs, failedSigs)

	// now see if we managed to get a threshold number of signatures
	s.log.Debugf("getThresholdConsensus: Marshaling consensus certificate for threshold verification for epoch %d", epoch)
	signedConsensus, err := ourConsensus.MarshalCertificate()
	if err != nil {
		s.log.Errorf("getThresholdConsensus: Failed to marshal consensus certificate for epoch %d: %s", epoch, err)
		return nil, err
	}

	s.log.Debugf("getThresholdConsensus: Verifying threshold signatures for epoch %d", epoch)
	_, good, bad, err := cert.VerifyThreshold(s.getVerifiers(), s.threshold, signedConsensus)

	s.log.Debugf("getThresholdConsensus: Threshold verification results for epoch %d: %d good signatures, %d bad signatures", epoch, len(good), len(bad))

	for _, b := range bad {
		authorityName := s.authorityNames[hash.Sum256From(b)]
		s.log.Errorf("getThresholdConsensus: Consensus NOT signed by authority %s for epoch %d", authorityName, epoch)
	}
	for _, g := range good {
		authorityName := s.authorityNames[hash.Sum256From(g)]
		s.log.Noticef("getThresholdConsensus: Consensus signed by authority %s for epoch %d", authorityName, epoch)
	}

	if err == nil {
		s.log.Noticef("getThresholdConsensus: SUCCESS! Threshold consensus achieved for epoch %d with %d/%d signatures", epoch, len(good), len(s.verifiers))
		s.log.Debugf("getThresholdConsensus: Consensus document for epoch %d: %v", epoch, ourConsensus)
		// Persist the document to disk.
		s.log.Debugf("getThresholdConsensus: Persisting consensus document to disk for epoch %d", epoch)
		s.persistDocument(epoch, signedConsensus)
		s.documents[epoch] = ourConsensus
		s.log.Noticef("getThresholdConsensus: Consensus document successfully persisted and stored for epoch %d", epoch)
		return ourConsensus, nil
	} else {
		s.log.Errorf("getThresholdConsensus: THRESHOLD VERIFICATION FAILED for epoch %d: %s", epoch, err)
		s.log.Errorf("getThresholdConsensus: Had %d good signatures, %d bad signatures, needed %d for threshold", len(good), len(bad), s.threshold)
	}
	s.log.Errorf("getThresholdConsensus: No consensus achieved for epoch %d", epoch)
	return nil, fmt.Errorf("no consensus found for epoch %d", epoch)
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

func (s *state) getDocument(descriptors []*pki.MixDescriptor, replicaDescriptors []*pki.ReplicaDescriptor, params *config.Parameters, srv []byte) *pki.Document {
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
		StorageReplicas:    replicaDescriptors,
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

	s.log.Debugf("verifyCommits: Starting SharedRandom commit verification for epoch %d", epoch)

	// check that each authority presented the same commit to every other authority
	badnodes := make(map[[publicKeyHashSize]byte]bool)
	comitted := make(map[[publicKeyHashSize]byte][]byte)
	revealed := make(map[[publicKeyHashSize]byte][]byte)

	certificateCount := 0
	if certs, ok := s.certificates[epoch]; ok {
		certificateCount = len(certs)
	}
	s.log.Debugf("verifyCommits: Processing %d certificates for epoch %d", certificateCount, epoch)

	// verify that each authority only submitted one commit value to all the authorities
	for pk, certificate := range s.certificates[epoch] {
		authorityName := s.authorityNames[pk]
		s.log.Debugf("verifyCommits: Processing certificate from authority %s (%x) for epoch %d", authorityName, pk, epoch)

		// skip badnodes
		if _, ok := badnodes[pk]; ok {
			s.log.Debugf("verifyCommits: Skipping bad authority %s (%x) for epoch %d", authorityName, pk, epoch)
			continue
		}

		commitCount := len(certificate.SharedRandomCommit)
		s.log.Debugf("verifyCommits: Authority %s has %d SharedRandom commits in certificate for epoch %d", authorityName, commitCount, epoch)

		for pk2, signedCommit := range certificate.SharedRandomCommit {
			authorityName2 := s.authorityNames[pk2]
			s.log.Debugf("verifyCommits: Processing commit from authority %s (%x) in certificate from %s for epoch %d", authorityName2, pk2, authorityName, epoch)

			// skip badnodes
			if _, ok := badnodes[pk2]; ok {
				s.log.Debugf("verifyCommits: Skipping commit from bad authority %s (%x) for epoch %d", authorityName2, pk2, epoch)
				continue
			}
			// verify that pk2 is authorized
			v, ok := s.reverseHash[pk2]
			if !ok {
				s.log.Errorf("verifyCommits: AUTHORIZATION FAILED - commit from invalid peer %x (%s) in certificate from %s for epoch %d", pk2, authorityName2, authorityName, epoch)
				badnodes[pk] = true
				break
			}
			s.log.Debugf("verifyCommits: Authorization check passed for authority %s in certificate from %s for epoch %d", authorityName2, authorityName, epoch)

			// verify that the allged commit is signed by pk2
			s.log.Debugf("verifyCommits: Verifying commit signature from authority %s in certificate from %s for epoch %d", authorityName2, authorityName, epoch)
			commit, err := cert.Verify(v, signedCommit)
			if err != nil {
				// pk didn't validate commit in its certificate!
				badnodes[pk] = true
				s.log.Errorf("verifyCommits: SIGNATURE VERIFICATION FAILED - invalid signature over commit from %s in certificate from %s, rejecting %s from consensus for epoch %d: %v", authorityName2, authorityName, authorityName, epoch, err)
				// do not bother checking any more of pk's SharedRandomCommits
				break
			}
			s.log.Debugf("verifyCommits: Commit signature verification passed for authority %s in certificate from %s for epoch %d", authorityName2, authorityName, epoch)
			// verify that the commit is accompanied by a reaveal
			s.log.Debugf("verifyCommits: Checking for reveal from authority %s in certificate from %s for epoch %d", authorityName2, authorityName, epoch)
			signedReveal, ok := certificate.SharedRandomReveal[pk2]
			if !ok {
				s.log.Errorf("verifyCommits: REVEAL MISSING - certificate from %s has commit for %s but not reveal for epoch %d", authorityName, authorityName2, epoch)
				badnodes[pk] = true
				// do not bother checking any more of pk's SharedRandomCommits
				break
			}
			s.log.Debugf("verifyCommits: Found reveal from authority %s in certificate from %s for epoch %d", authorityName2, authorityName, epoch)

			// verify that the alleged reveal is signed by pk2
			s.log.Debugf("verifyCommits: Verifying reveal signature from authority %s in certificate from %s for epoch %d", authorityName2, authorityName, epoch)
			reveal, err := cert.Verify(v, signedReveal)
			if err != nil {
				s.log.Errorf("verifyCommits: REVEAL SIGNATURE VERIFICATION FAILED - reveal in certificate from %s has invalid signature on reveal from %s for epoch %d: %v", authorityName, authorityName2, epoch, err)
				badnodes[pk] = true
				// do not bother checking any more of pk's SharedRandomCommits
				break
			}
			s.log.Debugf("verifyCommits: Reveal signature verification passed for authority %s in certificate from %s for epoch %d", authorityName2, authorityName, epoch)

			srv := new(pki.SharedRandom)
			srv.SetCommit(commit)
			// verify that the SharedRandom is for the correct epoch
			s.log.Debugf("verifyCommits: Verifying epoch in SharedRandom from authority %s in certificate from %s: got %d, expected %d", authorityName2, authorityName, srv.GetEpoch(), epoch)
			if srv.GetEpoch() != epoch {
				s.log.Errorf("verifyCommits: EPOCH MISMATCH - SharedRandomCommit in certificate from %s contains bad epoch %d from %s (expected %d)", authorityName, srv.GetEpoch(), authorityName2, epoch)
				badnodes[pk] = true
				badnodes[pk2] = true
				// do not bother checking any more of pk's SharedRandomCommits
				break
			}
			s.log.Debugf("verifyCommits: Epoch verification passed for SharedRandom from authority %s in certificate from %s for epoch %d", authorityName2, authorityName, epoch)

			// verify that the commit is validate by the revealed value
			s.log.Debugf("verifyCommits: Verifying commit-reveal pair from authority %s in certificate from %s for epoch %d", authorityName2, authorityName, epoch)
			if !srv.Verify(reveal) {
				s.log.Errorf("verifyCommits: COMMIT-REVEAL VERIFICATION FAILED - reveal in certificate from %s has invalid reveal from %s for epoch %d", authorityName, authorityName2, epoch)
				// pk should have validated the Reveal, and pk2 signed an invalid Reveal
				badnodes[pk] = true
				badnodes[pk2] = true
				break
			}
			s.log.Debugf("verifyCommits: Commit-reveal verification passed for authority %s in certificate from %s for epoch %d", authorityName2, authorityName, epoch)
			// see if we saw a different commit from pk2
			s.log.Debugf("verifyCommits: Checking for consistency of commit from authority %s for epoch %d", authorityName2, epoch)
			signedCommit2, ok := comitted[pk2]
			if ok {
				// check that the commits were the same
				if !bytes.Equal(signedCommit, signedCommit2) {
					s.log.Errorf("verifyCommits: COMMIT INCONSISTENCY - authority %s submitted commit %x to %s and previously submitted %x for epoch %d", authorityName2, signedCommit[:32], authorityName, signedCommit2[:32], epoch)
					badnodes[pk2] = true
				} else {
					s.log.Debugf("verifyCommits: Commit consistency verified for authority %s for epoch %d", authorityName2, epoch)
				}
			} else {
				// first time we saw a commit from pk2
				s.log.Debugf("verifyCommits: Recording first commit from authority %s for epoch %d", authorityName2, epoch)
				comitted[pk2] = signedCommit
			}
			// see if we saw a different reveal from pk2
			s.log.Debugf("verifyCommits: Checking for consistency of reveal from authority %s for epoch %d", authorityName2, epoch)
			signedReveal2, ok := revealed[pk2]
			if ok {
				if !bytes.Equal(signedReveal, signedReveal2) {
					s.log.Errorf("verifyCommits: REVEAL INCONSISTENCY - authority %s submitted reveal %x to %s and previously submitted %x for epoch %d", authorityName2, signedReveal[:32], authorityName, signedReveal2[:32], epoch)
					badnodes[pk2] = true
				} else {
					s.log.Debugf("verifyCommits: Reveal consistency verified for authority %s for epoch %d", authorityName2, epoch)
				}
			} else {
				s.log.Debugf("verifyCommits: Recording first reveal from authority %s for epoch %d", authorityName2, epoch)
				revealed[pk2] = signedReveal
			}
		}
		s.log.Debugf("verifyCommits: Completed processing certificate from authority %s for epoch %d", authorityName, epoch)
	}

	// ensure we have enough commits to make a threshold consensus
	s.log.Debugf("verifyCommits: Removing bad nodes from commit/reveal sets for epoch %d", epoch)
	for pk := range badnodes {
		authorityName := s.authorityNames[pk]
		s.log.Warningf("verifyCommits: Removing bad authority %s (%x) from consensus for epoch %d", authorityName, pk, epoch)
		delete(comitted, pk)
		delete(revealed, pk)
	}

	s.log.Noticef("verifyCommits: Verification complete for epoch %d: %d valid commits, %d valid reveals, %d bad nodes", epoch, len(comitted), len(revealed), len(badnodes))
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
	const (
		dialTimeout      = 30 * time.Second  // TCP connection timeout
		handshakeTimeout = 180 * time.Second // Wire handshake timeout
		responseTimeout  = 90 * time.Second  // Command exchange timeout
	)

	var conn net.Conn
	var err error
	for i, a := range peer.Addresses {
		u, err := url.Parse(a)
		if err != nil {
			continue
		}
		// Create dialer with timeout
		defaultDialer := &net.Dialer{Timeout: dialTimeout}
		ctx, cancelFn := context.WithTimeout(context.Background(), dialTimeout)
		conn, err = common.DialURL(u, ctx, defaultDialer.DialContext)
		cancelFn()
		if err == nil {
			defer conn.Close()
			break
		} else {
			s.log.Errorf("Got err from Peer: %v", err)
		}
		if i == len(peer.Addresses)-1 {
			return nil, err
		}
	}
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

	// Set handshake timeout before Initialize()
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err = session.Initialize(conn); err != nil {
		return nil, err
	}

	// Set response timeout for command exchange
	conn.SetDeadline(time.Now().Add(responseTimeout))
	err = session.SendCommand(cmd)
	if err != nil {
		return nil, err
	}

	// Keep response timeout for receiving reply
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
		s.Go(func() {
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
		})
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
		s.Go(func() {
			s.log.Noticef("Sending Vote to %s", peer.Identifier)
			resp, err := s.sendCommandToPeer(peer, cmd)
			if err != nil {
				s.log.Error("Failed to send vote to %s: %s", peer.Identifier, err)
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
		})
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
		s.Go(func() {
			s.log.Noticef("Sending Reveal to %s", peer.Identifier)
			resp, err := s.sendCommandToPeer(peer, cmd)
			if err != nil {
				s.log.Error("Failed to send reveal to %s: %s", peer.Identifier, err)
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
		})
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
		s.Go(func() {
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
		})
	}
}

func (s *state) tallyVotes(epoch uint64) ([]*pki.MixDescriptor, []*pki.ReplicaDescriptor, *config.Parameters, error) {
	if s.TryLock() {
		panic("write lock not held in tallyVotes(epoch)")
	}

	s.log.Debugf("tallyVotes: Starting vote tally for epoch %d", epoch)

	_, ok := s.votes[epoch]
	if !ok {
		s.log.Errorf("tallyVotes: No votes found for epoch %d", epoch)
		return nil, nil, nil, fmt.Errorf("no votes for epoch %v", epoch)
	}
	voteCount := len(s.votes[epoch])
	if voteCount < s.threshold {
		s.log.Errorf("tallyVotes: Insufficient votes for epoch %d: have %d, need %d", epoch, voteCount, s.threshold)
		return nil, nil, nil, fmt.Errorf("not enough votes for epoch %v", epoch)
	}
	s.log.Debugf("tallyVotes: Have sufficient votes for epoch %d: %d >= %d", epoch, voteCount, s.threshold)

	nodes := make([]*pki.MixDescriptor, 0)
	mixTally := make(map[string][]*pki.Document)
	mixParams := make(map[string][]*pki.Document)
	replicaTally := make(map[string][]*pki.Document)
	replicaNodes := make([]*pki.ReplicaDescriptor, 0)

	s.log.Debugf("tallyVotes: Processing %d votes for epoch %d", voteCount, epoch)
	for id, vote := range s.votes[epoch] {
		authorityName := s.authorityNames[id]
		s.log.Debugf("tallyVotes: Processing vote from authority %s (%x) for epoch %d", authorityName, id, epoch)

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
			s.log.Errorf("tallyVotes: Skipping vote from authority %s (%x) whose MixParameters failed to encode: %v", authorityName, id, err)
			continue
		}
		bs := b.String()
		if _, ok := mixParams[bs]; !ok {
			mixParams[bs] = make([]*pki.Document, 0)
		}
		mixParams[bs] = append(mixParams[bs], vote)
		s.log.Debugf("tallyVotes: Added parameters from authority %s to tally for epoch %d", authorityName, epoch)

		// include edge nodes in the tally.
		gatewayCount := len(vote.GatewayNodes)
		s.log.Debugf("tallyVotes: Processing %d gateway nodes from authority %s for epoch %d", gatewayCount, authorityName, epoch)
		for _, desc := range vote.GatewayNodes {
			rawDesc, err := desc.MarshalBinary()
			if err != nil {
				s.log.Errorf("tallyVotes: Skipping gateway node from authority %s (%x) whose MixDescriptor failed to encode: %v", authorityName, id, err)
				continue
			}
			k := string(rawDesc)
			if _, ok := mixTally[k]; !ok {
				mixTally[k] = make([]*pki.Document, 0)
			}
			mixTally[k] = append(mixTally[k], vote)
		}

		serviceCount := len(vote.ServiceNodes)
		s.log.Debugf("tallyVotes: Processing %d service nodes from authority %s for epoch %d", serviceCount, authorityName, epoch)
		for _, desc := range vote.ServiceNodes {
			rawDesc, err := desc.MarshalBinary()
			if err != nil {
				s.log.Errorf("tallyVotes: Skipping service node from authority %s (%x) whose MixDescriptor failed to encode: %v", authorityName, id, err)
				continue
			}
			k := string(rawDesc)
			if _, ok := mixTally[k]; !ok {
				mixTally[k] = make([]*pki.Document, 0)
			}
			mixTally[k] = append(mixTally[k], vote)
		}

		// include the rest of the mixes in the tally.
		topologyNodeCount := 0
		for _, l := range vote.Topology {
			topologyNodeCount += len(l)
		}
		s.log.Debugf("tallyVotes: Processing %d topology nodes from authority %s for epoch %d", topologyNodeCount, authorityName, epoch)
		for layerIdx, l := range vote.Topology {
			s.log.Debugf("tallyVotes: Processing layer %d with %d nodes from authority %s for epoch %d", layerIdx, len(l), authorityName, epoch)
			for _, desc := range l {
				rawDesc, err := desc.MarshalBinary()
				if err != nil {
					s.log.Errorf("tallyVotes: Skipping topology node from authority %s (%x) whose MixDescriptor failed to encode: %v", authorityName, id, err)
					continue
				}

				k := string(rawDesc)
				if _, ok := mixTally[k]; !ok {
					mixTally[k] = make([]*pki.Document, 0)
				}
				mixTally[k] = append(mixTally[k], vote)
			}
		}

		replicaCount := len(vote.StorageReplicas)
		s.log.Debugf("tallyVotes: Processing %d storage replicas from authority %s for epoch %d", replicaCount, authorityName, epoch)
		for _, desc := range vote.StorageReplicas {
			rawDesc, err := desc.Marshal()
			if err != nil {
				s.log.Errorf("tallyVotes: Skipping storage replica from authority %s (%x) whose ReplicaDescriptor failed to encode: %v", authorityName, id, err)
				continue
			}
			k := string(rawDesc)
			if _, ok := replicaTally[k]; !ok {
				replicaTally[k] = make([]*pki.Document, 0)
			}
			replicaTally[k] = append(replicaTally[k], vote)
		}
		s.log.Debugf("tallyVotes: Completed processing vote from authority %s: %d gateways, %d services, %d topology, %d replicas", authorityName, gatewayCount, serviceCount, topologyNodeCount, replicaCount)
	}
	s.log.Debugf("tallyVotes: Starting threshold evaluation for epoch %d", epoch)
	s.log.Debugf("tallyVotes: Have %d unique mix descriptors and %d unique replica descriptors to evaluate", len(mixTally), len(replicaTally))

	// include mixes that have a threshold of votes
	acceptedMixes := 0
	rejectedMixes := 0
	for rawDesc, votes := range mixTally {
		if len(votes) >= s.threshold {
			// this shouldn't fail as the descriptors have already been verified
			desc := new(pki.MixDescriptor)
			err := desc.UnmarshalBinary([]byte(rawDesc))
			if err != nil {
				s.log.Errorf("tallyVotes: Failed to unmarshal mix descriptor for epoch %d: %s", epoch, err)
				return nil, nil, nil, err
			}
			// only add nodes we have authorized
			if s.isDescriptorAuthorized(desc) {
				nodes = append(nodes, desc)
				acceptedMixes++
				s.log.Debugf("tallyVotes: Accepted mix descriptor %s with %d votes (>= %d threshold) for epoch %d", desc.Name, len(votes), s.threshold, epoch)
			} else {
				rejectedMixes++
				s.log.Warningf("tallyVotes: Rejected unauthorized mix descriptor %s for epoch %d", desc.Name, epoch)
			}
		} else {
			rejectedMixes++
			s.log.Debugf("tallyVotes: Rejected mix descriptor with insufficient votes: %d < %d threshold for epoch %d", len(votes), s.threshold, epoch)
		}
	}
	s.log.Debugf("tallyVotes: Mix descriptor evaluation complete for epoch %d: %d accepted, %d rejected", epoch, acceptedMixes, rejectedMixes)

	acceptedReplicas := 0
	rejectedReplicas := 0
	for rawDesc, votes := range replicaTally {
		if len(votes) >= s.threshold {
			// this shouldn't fail as the descriptors have already been verified
			desc := new(pki.ReplicaDescriptor)
			err := desc.Unmarshal([]byte(rawDesc))
			if err != nil {
				s.log.Errorf("tallyVotes: Failed to unmarshal replica descriptor for epoch %d: %s", epoch, err)
				return nil, nil, nil, err
			}
			// only add nodes we have authorized
			if s.isReplicaDescriptorAuthorized(desc) {
				replicaNodes = append(replicaNodes, desc)
				acceptedReplicas++
				s.log.Debugf("tallyVotes: Accepted replica descriptor %s with %d votes (>= %d threshold) for epoch %d", desc.Name, len(votes), s.threshold, epoch)
			} else {
				rejectedReplicas++
				s.log.Warningf("tallyVotes: Rejected unauthorized replica descriptor %s for epoch %d", desc.Name, epoch)
			}
		} else {
			rejectedReplicas++
			s.log.Debugf("tallyVotes: Rejected replica descriptor with insufficient votes: %d < %d threshold for epoch %d", len(votes), s.threshold, epoch)
		}
	}
	s.log.Debugf("tallyVotes: Replica descriptor evaluation complete for epoch %d: %d accepted, %d rejected", epoch, acceptedReplicas, rejectedReplicas)

	sortReplicaNodesByPublicKey(replicaNodes)
	s.log.Debugf("tallyVotes: Sorted replica nodes by public key for epoch %d", epoch)

	// include parameters that have a threshold of votes
	s.log.Debugf("tallyVotes: Evaluating %d parameter sets for threshold consensus for epoch %d", len(mixParams), epoch)
	paramSetsEvaluated := 0
	for bs, votes := range mixParams {
		paramSetsEvaluated++
		params := &config.Parameters{}
		d := gob.NewDecoder(strings.NewReader(bs))
		if err := d.Decode(params); err != nil {
			s.log.Errorf("tallyVotes: Failed to decode parameter set %d for epoch %d: %v", paramSetsEvaluated, epoch, err)
			continue
		}

		if len(votes) >= s.threshold {
			s.log.Noticef("tallyVotes: SUCCESS! Found parameter consensus with %d votes (>= %d threshold) for epoch %d", len(votes), s.threshold, epoch)
			sortNodesByPublicKey(nodes)
			s.log.Debugf("tallyVotes: Sorted mix nodes by public key for epoch %d", epoch)
			s.log.Noticef("tallyVotes: Final tally for epoch %d: %d mix nodes, %d replica nodes", epoch, len(nodes), len(replicaNodes))
			// successful tally
			return nodes, replicaNodes, params, nil
		} else if len(votes) >= s.dissenters {
			s.log.Warningf("tallyVotes: Parameter set %d has %d votes (>= %d dissenters but < %d threshold) for epoch %d", paramSetsEvaluated, len(votes), s.dissenters, s.threshold, epoch)
			continue
		} else {
			s.log.Debugf("tallyVotes: Parameter set %d has insufficient votes: %d < %d threshold for epoch %d", paramSetsEvaluated, len(votes), s.threshold, epoch)
		}
	}
	s.log.Errorf("tallyVotes: CONSENSUS FAILURE - no parameter set achieved threshold for epoch %d (evaluated %d sets)", epoch, paramSetsEvaluated)
	return nil, nil, nil, errors.New("consensus failure (mixParams empty)")
}

func (s *state) computeSharedRandom(epoch uint64, commits map[[publicKeyHashSize]byte][]byte, reveals map[[publicKeyHashSize]byte][]byte) ([]byte, error) {
	s.log.Debugf("computeSharedRandom: Starting SharedRandom computation for epoch %d", epoch)
	s.log.Debugf("computeSharedRandom: Have %d commits and %d reveals for epoch %d (threshold: %d)", len(commits), len(reveals), epoch, s.threshold)

	if len(commits) < s.threshold {
		s.log.Errorf("computeSharedRandom: INSUFFICIENT COMMITS for epoch %d: have %d, need %d", epoch, len(commits), s.threshold)
		for id := range commits {
			authorityName := s.authorityNames[id]
			s.log.Errorf("computeSharedRandom: Have commit for epoch %d from authority %s (%x)", epoch, authorityName, id)
		}
		return nil, errors.New("insufficient commits to make threshold vote")
	}
	s.log.Debugf("computeSharedRandom: Sufficient commits available for epoch %d", epoch)

	type Reveal struct {
		PublicKey [publicKeyHashSize]byte
		Digest    []byte
	}
	sortedreveals := make([]Reveal, 0, len(reveals))
	s.log.Debugf("computeSharedRandom: Processing %d reveals for epoch %d", len(reveals), epoch)

	for pk, srr := range reveals {
		authorityName := s.authorityNames[pk]
		s.log.Debugf("computeSharedRandom: Processing reveal from authority %s (%x) for epoch %d", authorityName, pk, epoch)
		digest, err := cert.GetCertified(srr)
		if err != nil {
			s.log.Errorf("computeSharedRandom: REVEAL PROCESSING FAILED for authority %s (%x) for epoch %d: %v", authorityName, pk, epoch, err)
			return nil, err
		}
		sortedreveals = append(sortedreveals, Reveal{PublicKey: pk, Digest: digest})
		s.log.Debugf("computeSharedRandom: Successfully processed reveal from authority %s for epoch %d", authorityName, epoch)
	}
	s.log.Debugf("computeSharedRandom: Processed all %d reveals for epoch %d", len(sortedreveals), epoch)

	s.log.Debugf("computeSharedRandom: Initializing BLAKE2b hasher for epoch %d", epoch)
	srv, err := blake2b.New256(nil)
	if err != nil {
		s.log.Errorf("computeSharedRandom: HASHER INITIALIZATION FAILED for epoch %d: %v", epoch, err)
		panic(err)
	}

	s.log.Debugf("computeSharedRandom: Writing shared-random prefix and epoch %d to hasher", epoch)
	srv.Write([]byte("shared-random"))
	srv.Write(epochToBytes(epoch))

	s.log.Debugf("computeSharedRandom: Sorting %d reveals for deterministic computation for epoch %d", len(sortedreveals), epoch)
	sort.Slice(sortedreveals, func(i, j int) bool {
		return string(sortedreveals[i].Digest) > string(sortedreveals[j].Digest)
	})

	s.log.Debugf("computeSharedRandom: Writing sorted reveals to hasher for epoch %d", epoch)
	for i, reveal := range sortedreveals {
		authorityName := s.authorityNames[reveal.PublicKey]
		s.log.Debugf("computeSharedRandom: Writing reveal %d from authority %s to hasher for epoch %d", i+1, authorityName, epoch)
		srv.Write(reveal.PublicKey[:])
		srv.Write(reveal.Digest)
	}

	// XXX: Tor also hashes in the previous srv or 32 bytes of 0x00
	//      How do we bootstrap a new authority?
	zeros := make([]byte, 32)
	if vot, ok := s.documents[s.votingEpoch-1]; ok {
		s.log.Debugf("computeSharedRandom: Writing previous SharedRandom value from epoch %d to hasher for epoch %d", s.votingEpoch-1, epoch)
		srv.Write(vot.SharedRandomValue)
	} else {
		s.log.Debugf("computeSharedRandom: No previous SharedRandom value available, writing zeros for epoch %d", epoch)
		srv.Write(zeros)
	}

	result := srv.Sum(nil)
	s.log.Noticef("computeSharedRandom: SUCCESS! Computed SharedRandom value for epoch %d: %x", epoch, result)
	return result, nil
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

func (s *state) isReplicaDescriptorAuthorized(desc *pki.ReplicaDescriptor) bool {
	pk := hash.Sum256(desc.IdentityKey)
	name, ok := s.authorizedReplicaNodes[pk]
	if !ok {
		return false
	}
	return name == desc.Name
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
	authorityName := s.authorityNames[pk]

	s.log.Debugf("onRevealUpload: Received reveal from authority %s (%x) for epoch %d", authorityName, pk, reveal.Epoch)

	// if not authorized
	_, ok := s.authorizedAuthorities[pk]
	if !ok {
		s.log.Errorf("onRevealUpload: AUTHORIZATION FAILED - reveal from authority %s (%x) not authorized for epoch %d", authorityName, pk, reveal.Epoch)
		resp.ErrorCode = commands.RevealNotAuthorized
		return &resp
	}
	s.log.Debugf("onRevealUpload: Authorization check passed for authority %s for epoch %d", authorityName, reveal.Epoch)

	// verify the signature on the payload
	s.log.Debugf("onRevealUpload: Verifying reveal signature from authority %s for epoch %d", authorityName, reveal.Epoch)
	s.log.Debugf("onRevealUpload: Reveal payload size: %d bytes from authority %s", len(reveal.Payload), authorityName)
	certified, err := cert.Verify(reveal.PublicKey, reveal.Payload)
	if err != nil {
		s.log.Errorf("onRevealUpload: SIGNATURE VERIFICATION FAILED - reveal from authority %s failed to verify for epoch %d: %v", authorityName, reveal.Epoch, err)
		s.log.Errorf("onRevealUpload: This is the exact error that caused 'RevealNotSigned' - authority %s submitted an invalid reveal signature", authorityName)
		s.log.Errorf("onRevealUpload: Reveal payload length: %d bytes", len(reveal.Payload))
		resp.ErrorCode = commands.RevealNotSigned
		return &resp
	}
	s.log.Debugf("onRevealUpload: Reveal signature verification passed for authority %s for epoch %d", authorityName, reveal.Epoch)

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
	authorityName := s.authorityNames[pk]

	s.log.Debugf("onVoteUpload: Received vote from authority %s (%x) for epoch %d", authorityName, pk, vote.Epoch)

	// if not authorized
	_, ok := s.authorizedAuthorities[pk]
	if !ok {
		s.log.Errorf("onVoteUpload: AUTHORIZATION FAILED - voter %s (%x) not authorized for epoch %d", authorityName, pk, vote.Epoch)
		resp.ErrorCode = commands.VoteNotAuthorized
		return &resp
	}
	s.log.Debugf("onVoteUpload: Authorization check passed for authority %s for epoch %d", authorityName, vote.Epoch)

	// XXX: this ought to use state, to prevent out-of-order protocol events, in case
	// we have any bugs in our implmementation
	s.log.Debugf("onVoteUpload: Validating epoch timing for authority %s: vote epoch %d, voting epoch %d", authorityName, vote.Epoch, s.votingEpoch)
	if vote.Epoch < s.votingEpoch {
		s.log.Errorf("onVoteUpload: EPOCH TOO EARLY - vote from %s received too early: %d < %d", authorityName, vote.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.VoteTooEarly
		return &resp
	}
	if vote.Epoch > s.votingEpoch {
		s.log.Errorf("onVoteUpload: EPOCH TOO LATE - vote from %s received too late: %d > %d", authorityName, vote.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.VoteTooLate
		return &resp
	}
	s.log.Debugf("onVoteUpload: Epoch validation passed for authority %s for epoch %d", authorityName, vote.Epoch)

	// haven't received a vote yet for this epoch
	if _, ok := s.votes[s.votingEpoch]; !ok {
		s.log.Debugf("onVoteUpload: Initializing votes map for epoch %d", s.votingEpoch)
		s.votes[s.votingEpoch] = make(map[[publicKeyHashSize]byte]*pki.Document)
	}

	// haven't received a commit yet for this epoch
	if _, ok = s.commits[s.votingEpoch]; !ok {
		s.log.Debugf("onVoteUpload: Initializing commits map for epoch %d", s.votingEpoch)
		s.commits[s.votingEpoch] = make(map[[publicKeyHashSize]byte][]byte)
	}

	// peer has already voted for this epoch
	_, ok = s.votes[s.votingEpoch][pk]
	if ok {
		s.log.Errorf("onVoteUpload: DUPLICATE VOTE - vote from authority %s already received for epoch %d", authorityName, s.votingEpoch)
		resp.ErrorCode = commands.VoteAlreadyReceived
		return &resp
	}
	s.log.Debugf("onVoteUpload: No duplicate vote detected for authority %s for epoch %d", authorityName, s.votingEpoch)

	// ensure vote.PublicKey verifies the payload (ie Vote has a signature from this peer)
	s.log.Debugf("onVoteUpload: Verifying vote signature from authority %s for epoch %d", authorityName, vote.Epoch)
	_, err := cert.Verify(vote.PublicKey, vote.Payload)
	if err != nil {
		s.log.Errorf("onVoteUpload: SIGNATURE VERIFICATION FAILED - vote from authority %s failed to verify for epoch %d: %v", authorityName, vote.Epoch, err)
		resp.ErrorCode = commands.VoteNotSigned
		return &resp
	}
	s.log.Debugf("onVoteUpload: Vote signature verification passed for authority %s for epoch %d", authorityName, vote.Epoch)

	s.log.Debugf("onVoteUpload: Parsing vote document from authority %s for epoch %d", authorityName, vote.Epoch)
	doc, err := s.doParseDocument(vote.Payload)
	if err != nil {
		s.log.Errorf("onVoteUpload: DOCUMENT PARSING FAILED - vote from authority %s failed signature verification for epoch %d: %v", authorityName, vote.Epoch, err)
		resp.ErrorCode = commands.VoteNotSigned
		return &resp
	}
	s.log.Debugf("onVoteUpload: Successfully parsed vote document from authority %s for epoch %d", authorityName, vote.Epoch)

	// Check that the deserialiezd payload was signed for the correct Epoch
	s.log.Debugf("onVoteUpload: Validating document epoch from authority %s: document epoch %d, expected %d", authorityName, doc.Epoch, s.votingEpoch)
	if doc.Epoch != s.votingEpoch {
		s.log.Errorf("onVoteUpload: EPOCH MISMATCH - vote from authority %s contains wrong epoch %d (expected %d)", authorityName, doc.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.VoteMalformed
		return &resp
	}
	s.log.Debugf("onVoteUpload: Document epoch validation passed for authority %s for epoch %d", authorityName, doc.Epoch)

	// extract commit from document and verify that it was signed by this peer
	// IsDocumentWellFormed has already verified that any commit is for
	// this Epoch and is signed by a known verifier
	s.log.Debugf("onVoteUpload: Extracting SharedRandom commit from vote document from authority %s for epoch %d", authorityName, vote.Epoch)
	commit, ok := doc.SharedRandomCommit[pk]
	if !ok {
		// It's possible that an authority submitted another authoritys vote on its behalf,
		// but we are not going to allow that behavior as it is not specified.
		s.log.Errorf("onVoteUpload: COMMIT MISSING - vote from authority %s did not contain SharedRandom commit for epoch %d", authorityName, vote.Epoch)
		resp.ErrorCode = commands.VoteMalformed
		return &resp
	}
	s.log.Debugf("onVoteUpload: Successfully extracted SharedRandom commit from authority %s for epoch %d", authorityName, vote.Epoch)

	// save the vote
	s.log.Debugf("onVoteUpload: Saving vote from authority %s for epoch %d", authorityName, vote.Epoch)
	s.votes[s.votingEpoch][pk] = doc
	// save the commit
	s.log.Debugf("onVoteUpload: Saving SharedRandom commit from authority %s for epoch %d", authorityName, vote.Epoch)
	s.commits[s.votingEpoch][pk] = commit

	currentVoteCount := len(s.votes[s.votingEpoch])
	s.log.Noticef("onVoteUpload: SUCCESS! Vote accepted from authority %s for epoch %d (total votes: %d/%d)", authorityName, vote.Epoch, currentVoteCount, len(s.authorizedAuthorities))
	s.log.Debugf("onVoteUpload: Vote document from authority %s for epoch %d:\n%s", authorityName, vote.Epoch, doc)
	resp.ErrorCode = commands.VoteOk
	return &resp
}

func (s *state) onSigUpload(sig *commands.Sig) commands.Command {
	s.Lock()
	defer s.Unlock()
	resp := commands.SigStatus{}
	pk := hash.Sum256From(sig.PublicKey)
	authorityName := s.authorityNames[pk]

	s.log.Debugf("onSigUpload: Received signature from authority %s (%x) for epoch %d", authorityName, pk, sig.Epoch)

	_, ok := s.authorizedAuthorities[pk]
	if !ok {
		s.log.Errorf("onSigUpload: AUTHORIZATION FAILED - signature from authority %s (%x) not authorized for epoch %d", authorityName, pk, sig.Epoch)
		resp.ErrorCode = commands.SigNotAuthorized
		return &resp
	}
	s.log.Debugf("onSigUpload: Authorization check passed for authority %s for epoch %d", authorityName, sig.Epoch)

	s.log.Debugf("onSigUpload: Validating epoch timing for authority %s: signature epoch %d, voting epoch %d", authorityName, sig.Epoch, s.votingEpoch)
	if sig.Epoch < s.votingEpoch {
		s.log.Errorf("onSigUpload: EPOCH TOO EARLY - signature from authority %s received too early: %d < %d", authorityName, sig.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.SigTooEarly
		return &resp
	}
	if sig.Epoch > s.votingEpoch {
		s.log.Errorf("onSigUpload: EPOCH TOO LATE - signature from authority %s received too late: %d > %d", authorityName, sig.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.SigTooLate
		return &resp
	}
	s.log.Debugf("onSigUpload: Epoch validation passed for authority %s for epoch %d", authorityName, sig.Epoch)

	s.log.Debugf("onSigUpload: Verifying signature from authority %s for epoch %d", authorityName, sig.Epoch)
	verified, err := cert.Verify(sig.PublicKey, sig.Payload)
	if err != nil {
		s.log.Errorf("onSigUpload: SIGNATURE VERIFICATION FAILED - signature from authority %s failed verification for epoch %d: %v", authorityName, sig.Epoch, err)
		resp.ErrorCode = commands.SigNotSigned
		return &resp
	}
	s.log.Debugf("onSigUpload: Signature verification passed for authority %s for epoch %d", authorityName, sig.Epoch)

	// haven't received a sig yet for this epoch
	if _, ok := s.signatures[s.votingEpoch]; !ok {
		s.log.Debugf("onSigUpload: Initializing signatures map for epoch %d", s.votingEpoch)
		s.signatures[s.votingEpoch] = make(map[[publicKeyHashSize]byte]*cert.Signature)
	}

	// peer has not yet submitted a signature
	s.log.Debugf("onSigUpload: Checking for duplicate signature from authority %s for epoch %d", authorityName, sig.Epoch)
	if !s.dupSig(*sig) {
		s.log.Debugf("onSigUpload: No duplicate signature detected, processing signature from authority %s for epoch %d", authorityName, sig.Epoch)
		csig := new(cert.Signature)
		err := csig.Unmarshal(verified)
		if err != nil {
			resp.ErrorCode = commands.SigInvalid
			s.log.Errorf("onSigUpload: SIGNATURE DESERIALIZATION FAILED - signature failed to deserialize from authority %s for epoch %d: %v", authorityName, sig.Epoch, err)
			return &resp
		}
		s.log.Debugf("onSigUpload: Successfully deserialized signature from authority %s for epoch %d", authorityName, sig.Epoch)

		s.signatures[s.votingEpoch][hash.Sum256From(sig.PublicKey)] = csig
		currentSigCount := len(s.signatures[s.votingEpoch])
		s.log.Noticef("onSigUpload: SUCCESS! Signature accepted from authority %s for epoch %d (total signatures: %d/%d)", authorityName, sig.Epoch, currentSigCount, len(s.authorizedAuthorities))
		resp.ErrorCode = commands.SigOk
		return &resp
	} else {
		// peer is behaving strangely
		// error; two sigs from same peer
		s.log.Errorf("onSigUpload: DUPLICATE SIGNATURE - authority %s attempted to submit multiple signatures for epoch %d", authorityName, sig.Epoch)
		resp.ErrorCode = commands.SigAlreadyReceived
		return &resp
	}
}

func (s *state) onReplicaDescriptorUpload(rawDesc []byte, desc *pki.ReplicaDescriptor, epoch uint64) error {
	s.Lock()
	defer s.Unlock()

	// Note: Caller ensures that the epoch is the current epoch +- 1.
	pk := hash.Sum256(desc.IdentityKey)

	// Get the public key -> descriptor map for the epoch.
	_, ok := s.replicaDescriptors[epoch]
	if !ok {
		s.replicaDescriptors[epoch] = make(map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor)
	}

	// Check for redundant uploads.
	d, ok := s.replicaDescriptors[epoch][pk]
	if ok {
		// If the descriptor changes, then it will be rejected to prevent
		// nodes from reneging on uploads.
		serialized, err := d.Marshal()
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
		bkt := tx.Bucket([]byte(replicaDescriptorsBucket))
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
	s.replicaDescriptors[epoch][pk] = desc

	s.log.Noticef("Node %x: Successfully submitted replica descriptor for epoch %v.", pk, epoch)
	s.onUpdate()
	return nil
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
		return d.MarshalCertificate()
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
		replicaDescsBkt, err := tx.CreateBucketIfNotExists([]byte(replicaDescriptorsBucket))
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

			// Restore the replica descriptors.
			for _, epoch := range epochs {
				epochBytes := epochToBytes(epoch)
				eDescsBkt := replicaDescsBkt.Bucket(epochBytes)
				if eDescsBkt == nil {
					s.log.Debugf("No persisted Descriptors for epoch: %v.", epoch)
					continue
				}
				c := eDescsBkt.Cursor()
				for wantHash, rawDesc := c.First(); wantHash != nil; wantHash, rawDesc = c.Next() {
					if len(wantHash) != publicKeyHashSize {
						panic("stored hash should be 32 bytes")
					}
					desc := new(pki.ReplicaDescriptor)
					err := desc.Unmarshal(rawDesc)
					if err != nil {
						s.log.Errorf("Failed to validate persisted descriptor: %v", err)
						continue
					}
					idHash := hash.Sum256(desc.IdentityKey)
					if !hmac.Equal(wantHash, idHash[:]) {
						s.log.Errorf("Discarding persisted descriptor: key mismatch")
						continue
					}

					if !s.isReplicaDescriptorAuthorized(desc) {
						s.log.Warningf("Discarding persisted descriptor: %v", desc)
						continue
					}

					_, ok := s.replicaDescriptors[epoch]
					if !ok {
						s.replicaDescriptors[epoch] = make(map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor)
					}

					s.replicaDescriptors[epoch][hash.Sum256(desc.IdentityKey)] = desc
					s.log.Debugf("Restored replica descriptor for epoch %v: %+v", epoch, desc)
				}
			}

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
	st.authorizedReplicaNodes = make(map[[publicKeyHashSize]byte]string)
	for _, v := range st.s.cfg.StorageReplicas {
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
		st.authorizedReplicaNodes[pk] = v.Identifier
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
	st.replicaDescriptors = make(map[uint64]map[[publicKeyHashSize]byte]*pki.ReplicaDescriptor)
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
		s.Go(func() {
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
		})
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

func sortReplicaNodesByPublicKey(nodes []*pki.ReplicaDescriptor) {
	dTos := func(d *pki.ReplicaDescriptor) string {
		pk := hash.Sum256(d.IdentityKey)
		return string(pk[:])
	}
	sort.Slice(nodes, func(i, j int) bool { return dTos(nodes[i]) < dTos(nodes[j]) })
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
	s.log.Debugf("doCommit: Generating SharedRandom Commit for epoch %d", epoch)
	s.log.Debugf("doCommit: Our identity hash: %x", s.identityPubKeyHash())

	srv := new(pki.SharedRandom)
	commit, err := srv.Commit(epoch)
	if err != nil {
		s.log.Errorf("doCommit: Failed to generate commit for epoch %d: %v", epoch, err)
		return nil, err
	}
	s.log.Debugf("doCommit: Successfully generated commit for epoch %d", epoch)

	// sign the serialized commit
	s.log.Debugf("doCommit: Signing commit for epoch %d", epoch)
	signedCommit, err := cert.Sign(s.s.identityPrivateKey, s.s.identityPublicKey, commit, epoch)
	if err != nil {
		s.log.Errorf("doCommit: Failed to sign commit for epoch %d: %v", epoch, err)
		return nil, err
	}
	s.log.Debugf("doCommit: Successfully signed commit for epoch %d", epoch)

	// sign the reveal
	s.log.Debugf("doCommit: Signing reveal for epoch %d", epoch)
	signedReveal, err := cert.Sign(s.s.identityPrivateKey, s.s.identityPublicKey, srv.Reveal(), epoch)
	if err != nil {
		s.log.Errorf("doCommit: Failed to sign reveal for epoch %d: %v", epoch, err)
		return nil, err
	}
	s.log.Debugf("doCommit: Successfully signed reveal for epoch %d", epoch)

	// save our commit
	if _, ok := s.commits[epoch]; !ok {
		s.log.Debugf("doCommit: Creating commits map for epoch %d", epoch)
		s.commits[epoch] = make(map[[pki.PublicKeyHashSize]byte][]byte)
	}
	s.commits[epoch][s.identityPubKeyHash()] = signedCommit
	s.log.Debugf("doCommit: Stored our commit for epoch %d", epoch)

	// save our reveal
	if _, ok := s.reveals[epoch]; !ok {
		s.log.Debugf("doCommit: Creating reveals map for epoch %d", epoch)
		s.reveals[epoch] = make(map[[pki.PublicKeyHashSize]byte][]byte)
	}
	s.reveals[epoch][s.identityPubKeyHash()] = signedReveal
	s.log.Debugf("doCommit: Stored our reveal for epoch %d", epoch)
	return signedCommit, nil
}

func (s *state) reveal(epoch uint64) []byte {
	s.log.Debugf("reveal: Retrieving reveal for epoch %d", epoch)
	s.log.Debugf("reveal: Our identity hash: %x", s.identityPubKeyHash())

	// Check if reveals map exists for this epoch
	if _, ok := s.reveals[epoch]; !ok {
		s.log.Errorf("reveal: No reveals map exists for epoch %d", epoch)
	} else {
		s.log.Debugf("reveal: Reveals map exists for epoch %d with %d entries", epoch, len(s.reveals[epoch]))
	}

	// Check if commits map exists and has our commit
	if commits, ok := s.commits[epoch]; ok {
		if _, hasOurCommit := commits[s.identityPubKeyHash()]; hasOurCommit {
			s.log.Debugf("reveal: We DO have our commit stored for epoch %d", epoch)
		} else {
			s.log.Errorf("reveal: We do NOT have our commit stored for epoch %d", epoch)
		}
		s.log.Debugf("reveal: Total commits for epoch %d: %d", epoch, len(commits))
	} else {
		s.log.Errorf("reveal: No commits map exists for epoch %d", epoch)
	}

	signed, ok := s.reveals[epoch][s.identityPubKeyHash()]
	if !ok {
		fatalErr := fmt.Errorf("REVEAL FATAL: reveal() called without commit for epoch %d - this indicates a critical SharedRandom protocol violation", epoch)
		s.log.Errorf("reveal: %v", fatalErr)
		s.log.Errorf("reveal: Available reveals for epoch %d: %d", epoch, len(s.reveals[epoch]))
		for pk := range s.reveals[epoch] {
			authorityName := s.authorityNames[pk]
			s.log.Errorf("reveal: Have reveal from authority %s (%x)", authorityName, pk)
		}
		s.s.fatalErrCh <- fatalErr
	}
	s.log.Debugf("reveal: Successfully retrieved reveal for epoch %d", epoch)
	return signed
}
