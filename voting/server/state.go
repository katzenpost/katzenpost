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
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/authority/voting/client"
	"github.com/katzenpost/authority/voting/internal/s11n"
	"github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/cert"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
	"github.com/katzenpost/core/worker"
	"golang.org/x/crypto/sha3"
	"gopkg.in/op/go-logging.v1"
)

const (
	descriptorsBucket     = "descriptors"
	documentsBucket       = "documents"
	stateAcceptDescriptor = "accept_desc"
	stateAcceptVote       = "accept_vote"
	stateAcceptReveal     = "accept_reveal"
	stateAcceptSignature  = "accept_signature"
	stateBootstrap        = "bootstrap"
)

var (
	errGone   = errors.New("authority: Requested epoch will never get a Document")
	errNotYet = errors.New("authority: Document is not ready yet")
)

var (
	mixPublishDeadline, authorityVoteDeadline, authorityRevealDeadline, publishConsensusDeadline time.Duration
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

	authorizedMixes       map[[eddsa.PublicKeySize]byte]bool
	authorizedProviders   map[[eddsa.PublicKeySize]byte]string
	authorizedAuthorities map[[eddsa.PublicKeySize]byte]bool

	documents    map[uint64]*document
	descriptors  map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor
	votes        map[uint64]map[[eddsa.PublicKeySize]byte]*document
	reveals      map[uint64]map[[eddsa.PublicKeySize]byte][]byte
	certificates map[uint64]map[[eddsa.PublicKeySize]byte][]byte

	updateCh chan interface{}

	votingEpoch uint64
	verifiers   []cert.Verifier
	threshold   int
	dissenters  int
	state       string
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
	s.log.Debugf("Current epoch %d", epoch)

	switch s.state {
	case stateBootstrap:
		s.log.Debugf("Bootstrapping for %d", s.votingEpoch)
		s.backgroundFetchConsensus(epoch - 1)
		s.backgroundFetchConsensus(epoch)
		s.state = stateAcceptDescriptor
		sleep = mixPublishDeadline - elapsed
	case stateAcceptDescriptor:
		if !s.hasEnoughDescriptors(s.descriptors[s.votingEpoch]) {
			s.log.Debugf("Not voting because insufficient descriptors uploaded for epoch %d!", s.votingEpoch)
			sleep = nextEpoch
			s.votingEpoch = epoch + 2 // wait until next epoch begins and bootstrap
			s.state = stateBootstrap
			break
		}
		if !s.voted(s.votingEpoch) {
			s.log.Debugf("Voting for epoch %v", s.votingEpoch)
			s.vote(s.votingEpoch)
			s.state = stateAcceptVote
			sleep = authorityVoteDeadline - elapsed
		}
	case stateAcceptVote:
		s.reveal(s.votingEpoch)
		s.state = stateAcceptReveal
		sleep = authorityRevealDeadline - elapsed
	case stateAcceptReveal:
		// we have collect all of the reveal values
		// now we compute the shared random value
		// and produce a consensus from votes
		if !s.isTabulated(s.votingEpoch) {
			s.log.Debugf("Tabulating for epoch %v", s.votingEpoch)
			s.tabulate(s.votingEpoch)
		}
		s.state = stateAcceptSignature
		sleep = publishConsensusDeadline - elapsed
	case stateAcceptSignature:
		s.log.Debugf("Combining signatures for epoch %v", s.votingEpoch)
		s.consense(s.votingEpoch)
		if _, ok := s.documents[s.votingEpoch]; ok {
			s.state = stateAcceptDescriptor
			if s.votingEpoch == epoch {
				// either we bootstrapped before the publish deadline
				// or we default to 30 seconds
				sleep = mixPublishDeadline - elapsed
			} else {
				sleep = mixPublishDeadline + nextEpoch
			}
			s.votingEpoch++
		} else {
			// failed to make consensus. try to join next round.
			s.state = stateBootstrap
			s.votingEpoch = epoch + 2 // vote on epoch+2 in epoch+1
			sleep = nextEpoch
		}
	default:
	}
	s.pruneDocuments()
	if s.votingEpoch <= epoch || sleep < 0 {
		sleep = 30 * time.Second
	}
	s.log.Debugf("authority: FSM in state %v until %s", s.state, sleep)
	s.Unlock()
	return time.After(sleep)
}

func (s *state) consense(epoch uint64) {
	// if we have a document, see if the other signatures make a consensus
	// if we do not make a consensus with our document iterate over the
	// other documents and see if the signatures make a consensus

	certificates, ok := s.certificates[epoch]
	if !ok {
		s.log.Errorf("No certificates for epoch %d", epoch)
		return
	}

	for pk, c := range certificates {
		for jk, d := range certificates {
			if pk == jk {
				continue // skip adding own signature
			}
			kjk := new(eddsa.PublicKey)
			kjk.FromBytes(jk[:])
			if ds, err := cert.GetSignature(jk[:], d); err == nil {
				if sc, err := cert.AddSignature(kjk, *ds, c); err == nil {
					c = sc
				}
			}
		}
		if _, good, _, err := cert.VerifyThreshold(s.verifiers, s.threshold, c); err == nil {
			if pDoc, _, err := s11n.VerifyAndParseDocument(c, good[0]); err == nil {
				s.documents[epoch] = &document{doc: pDoc, raw: c}
				s.log.Noticef("Consensus made for epoch %d with %d/%d signatures", epoch, len(good), len(s.verifiers))
				for _, g := range good {
					id := base64.StdEncoding.EncodeToString(g.Identity())
					s.log.Noticef("Consensus signed by %s", id)
				}
				return
			}
		}
	}
	s.log.Errorf("No consensus found for epoch %d", epoch)
	return
}

func (s *state) identityPubKey() [eddsa.PublicKeySize]byte {
	return s.s.identityKey.PublicKey().ByteArray()
}

func (s *state) voted(epoch uint64) bool {
	if _, ok := s.votes[epoch]; ok {
		if _, ok := s.votes[epoch][s.identityPubKey()]; ok {
			return true
		}
	}
	return false
}

func (s *state) getDocument(descriptors []*descriptor, params *config.Parameters, srv []byte) *s11n.Document {
	// Carve out the descriptors between providers and nodes.
	var providers [][]byte
	var nodes []*descriptor
	for _, v := range descriptors {
		if v.desc.Layer == pki.LayerProvider {
			providers = append(providers, v.raw)
		} else {
			nodes = append(nodes, v)
		}
	}

	// Assign nodes to layers.
	var topology [][][]byte
	// XXX: should a bootstrapping authority fetch prior consensus' Topology from another authority?

	// TODO: We could re-use a prior topology for a configurable number of epochs

	// We prefer to not randomize the topology if there is an existing topology to avoid
	// partitioning the client anonymity set when messages from an earlier epoch are
	// differentiable as such because of topology violations in the present epoch.
	if d, ok := s.documents[s.votingEpoch-1]; ok {
		topology = s.generateTopology(nodes, d.doc, srv)
	} else {
		// XXX: ask another authority for a consensus
		// (this might be better placed at bootstrap)
		// Or, this authority will vote with a random
		// topology and never reach consenus with the other authorities
		topology = s.generateRandomTopology(nodes, srv)
	}

	// Build the Document.
	doc := &s11n.Document{
		Epoch:             s.votingEpoch,
		MixLambda:         params.MixLambda,
		MixMaxDelay:       params.MixMaxDelay,
		SendLambda:        params.SendLambda,
		SendShift:         params.SendShift,
		SendMaxInterval:   params.SendMaxInterval,
		DropLambda:        params.DropLambda,
		DropShift:         params.DropShift,
		DropMaxInterval:   params.DropMaxInterval,
		LoopLambda:        params.LoopLambda,
		LoopShift:         params.LoopShift,
		LoopMaxInterval:   params.LoopMaxInterval,
		Topology:          topology,
		Providers:         providers,
		SharedRandomValue: srv,
	}
	return doc
}

// SharedRandom is a container for commit-and-reveal protocol messages
type SharedRandom struct {
	epoch  uint64
	commit []byte
	reveal []byte
}

// Commit produces a SharedRandom commit value for the given epoch
func (s *SharedRandom) Commit(epoch uint64) ([]byte, error) {
	// pick a random number RN
	// COMMIT = Uint64(epoch) || H(REVEAL)
	// REVEAL = Uint64(epoch) || H(RN)
	rn := make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, rn)
	if err != nil || n != 32 {
		return nil, err
	}
	s.epoch = epoch
	s.commit = make([]byte, s11n.SharedRandomLength)
	s.reveal = make([]byte, s11n.SharedRandomLength)
	binary.BigEndian.PutUint64(s.reveal, epoch)
	binary.BigEndian.PutUint64(s.commit, epoch)
	reveal := sha3.Sum256(rn)
	copy(s.reveal[8:], reveal[:])
	commit := sha3.Sum256(s.reveal)
	copy(s.commit[8:], commit[:])
	return s.commit, nil
}

// GetCommit returns the commit value
func (s *SharedRandom) GetCommit() []byte {
	return s.commit
}

// SetCommit sets the commit value
func (s *SharedRandom) SetCommit(rawCommit []byte) {
	s.epoch = binary.BigEndian.Uint64(rawCommit[0:8])
	s.commit = rawCommit
}

// Verify checks that the reveal value verifies the commit value
func (s *SharedRandom) Verify(reveal []byte) bool {
	if len(reveal) != s11n.SharedRandomLength {
		return false
	}
	epoch := binary.BigEndian.Uint64(reveal[0:8])
	allegedCommit := sha3.Sum256(reveal)
	if epoch == s.epoch {
		if bytes.Equal(s.commit[8:], allegedCommit[:]) {
			return true
		}
	}
	return false
}

// Reveal returns the reveal value
func (s *SharedRandom) Reveal() []byte {
	return s.reveal
}

func (s *state) reveal(epoch uint64) {
	if reveal, ok := s.reveals[epoch][s.identityPubKey()]; ok {
		go s.sendRevealToAuthorities(reveal, epoch)
	}
}

func (s *state) vote(epoch uint64) {
	descriptors := []*descriptor{}
	for _, desc := range s.descriptors[epoch] {
		descriptors = append(descriptors, desc)
	}
	srv := new(SharedRandom)
	commit, err := srv.Commit(epoch)
	if err != nil {
		s.s.fatalErrCh <- err
	}

	// save our own reveal
	if _, ok := s.reveals[epoch]; !ok {
		s.reveals[epoch] = make(map[[eddsa.PublicKeySize]byte][]byte)
	}
	if _, ok := s.reveals[epoch][s.identityPubKey()]; !ok {
		s.reveals[epoch][s.identityPubKey()] = srv.Reveal()
		// XXX persist reveals to database?
	} else {
		s.log.Errorf("failure: reveal already present, this should never happen.")
		err := errors.New("failure: reveal already present, this should never happen")
		s.s.fatalErrCh <- err
		return
	}

	// vote topology is irrelevent.
	var zeros [32]byte
	vote := s.getDocument(descriptors, s.s.cfg.Parameters, zeros[:])
	vote.SharedRandomCommit = commit
	signedVote := s.sign(vote)
	if signedVote == nil {
		err := errors.New("failure: signing vote failed")
		s.s.fatalErrCh <- err
		return
	}

	// save our own vote
	if _, ok := s.votes[epoch]; !ok {
		s.votes[epoch] = make(map[[eddsa.PublicKeySize]byte]*document)
	}
	if _, ok := s.votes[epoch][s.identityPubKey()]; !ok {
		s.votes[epoch][s.identityPubKey()] = signedVote
		// XXX persist votes to database?
	} else {
		s.log.Errorf("failure: vote already present, this should never happen.")
		err := errors.New("failure: vote already present, this should never happen")
		s.s.fatalErrCh <- err
		return
	}
	s.sendVoteToAuthorities(signedVote.raw, epoch)
}

func (s *state) sign(doc *s11n.Document) *document {
	// Serialize and sign the Document.
	signed, err := s11n.SignDocument(s.s.identityKey, doc)
	if err != nil {
		// This should basically always succeed.
		s.log.Errorf("Failed to sign document: %v", err)
		s.s.fatalErrCh <- err
		return nil
	}

	// Ensure the document is sane.
	pDoc, _, err := s11n.VerifyAndParseDocument([]byte(signed), s.s.identityKey.PublicKey())
	if err != nil {
		// This should basically always succeed.
		s.log.Errorf("Signed document failed validation: %v", err)
		s.s.fatalErrCh <- err
		return nil
	}
	return &document{
		doc: pDoc,
		raw: []byte(signed),
	}
}

func (s *state) hasEnoughDescriptors(m map[[eddsa.PublicKeySize]byte]*descriptor) bool {
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

func (s *state) sendRevealToPeer(peer *config.AuthorityPeer, reveal []byte, epoch uint64) error {
	conn, err := net.Dial("tcp", peer.Addresses[0]) // XXX
	if err != nil {
		return err
	}
	defer conn.Close()
	s.s.Add(1)
	defer s.s.Done()
	cfg := &wire.SessionConfig{
		Authenticator:     s,
		AdditionalData:    []byte(""),
		AuthenticationKey: s.s.linkKey,
		RandomReader:      rand.Reader,
	}
	session, err := wire.NewSession(cfg, true)
	if err != nil {
		return err
	}
	defer session.Close()

	if err = session.Initialize(conn); err != nil {
		return err
	}
	var digest [32]byte
	copy(digest[:], reveal[8:])
	cmd := &commands.Reveal{
		Epoch:     epoch,
		PublicKey: s.s.IdentityKey(),
		Digest:    digest,
	}
	err = session.SendCommand(cmd)
	if err != nil {
		return err
	}
	resp, err := session.RecvCommand()
	if err != nil {
		return err
	}
	r, ok := resp.(*commands.RevealStatus)
	if !ok {
		return fmt.Errorf("Reveal response resulted in unexpected reply: %T", resp)
	}
	switch r.ErrorCode {
	case commands.RevealOk:
		return nil
	case commands.RevealTooLate:
		return errors.New("reveal was too late")
	case commands.RevealTooEarly:
		return errors.New("reveal was too early")
	case commands.RevealAlreadyReceived:
		return errors.New("reveal already received by authority")
	case commands.RevealNotAuthorized:
		return errors.New("reveal rejected by authority: Not Authorized")
	default:
		return fmt.Errorf("reveal rejected by authority: unknown error code received")
	}
	return nil

}
func (s *state) sendVoteToPeer(peer *config.AuthorityPeer, vote []byte, epoch uint64) error {
	// get a connector here
	conn, err := net.Dial("tcp", peer.Addresses[0]) // XXX
	if err != nil {
		return err
	}
	defer conn.Close()
	s.s.Add(1)
	defer s.s.Done()
	cfg := &wire.SessionConfig{
		Authenticator:     s,
		AdditionalData:    []byte(""),
		AuthenticationKey: s.s.linkKey,
		RandomReader:      rand.Reader,
	}
	session, err := wire.NewSession(cfg, true)
	if err != nil {
		return err
	}
	defer session.Close()

	if err = session.Initialize(conn); err != nil {
		return err
	}
	cmd := &commands.Vote{
		Epoch:     epoch,
		PublicKey: s.s.IdentityKey(),
		Payload:   vote,
	}
	err = session.SendCommand(cmd)
	if err != nil {
		return err
	}
	resp, err := session.RecvCommand()
	if err != nil {
		return err
	}
	r, ok := resp.(*commands.VoteStatus)
	if !ok {
		return fmt.Errorf("Vote response resulted in unexpected reply: %T", resp)
	}
	switch r.ErrorCode {
	case commands.VoteOk:
		return nil
	case commands.VoteTooLate:
		return errors.New("vote was too late")
	case commands.VoteTooEarly:
		return errors.New("vote was too early")
	default:
		return fmt.Errorf("vote rejected by authority: unknown error code received")
	}
	return nil
}

// IsPeerValid authenticates the remote peer's credentials
// for our link layer wire protocol as specified by
// the PeerAuthenticator interface in core/wire/session.go
func (s *state) IsPeerValid(creds *wire.PeerCredentials) bool {
	var ad [eddsa.PublicKeySize]byte
	copy(ad[:], creds.AdditionalData)
	_, ok := s.authorizedAuthorities[ad]
	if ok {
		return true
	}
	return false
}

// sendRevealToAuthorities sends a Shared Random Reveal command to
// all Directory Authorities
func (s *state) sendRevealToAuthorities(reveal []byte, epoch uint64) {
	s.log.Noticef("Sending Shared Random Reveal for epoch %v, to all Directory Authorities.", epoch)

	for _, peer := range s.s.cfg.Authorities {
		go s.sendRevealToPeer(peer, reveal, epoch)
	}

}

// sendVoteToAuthorities sends s.descriptors[epoch] to
// all Directory Authorities
func (s *state) sendVoteToAuthorities(vote []byte, epoch uint64) {
	// Lock is held (called from the onWakeup hook).

	s.log.Noticef("Sending Document for epoch %v, to all Directory Authorities.", s.votingEpoch)

	for _, peer := range s.s.cfg.Authorities {
		go s.sendVoteToPeer(peer, vote, epoch)
	}
}

func (s *state) tallyVotes(epoch uint64) ([]*descriptor, *config.Parameters, error) {
	// Lock is held (called from the onWakeup hook).
	_, ok := s.votes[epoch]
	if !ok {
		return nil, nil, fmt.Errorf("No votes for epoch %v!", epoch)
	}
	if len(s.votes[epoch]) <= s.threshold {
		return nil, nil, fmt.Errorf("Not enough votes for epoch %v!", epoch)
	}

	nodes := make([]*descriptor, 0)
	mixTally := make(map[string][]*s11n.Document)
	mixParams := make(map[string][]*s11n.Document)
	for pk, voteDoc := range s.votes[epoch] {
		srv := new(SharedRandom)
		// Parse the payload bytes into the s11n.Document
		// so that we can access the mix descriptors + sigs
		// The votes have already been validated.

		if _, ok := s.reveals[epoch][pk]; !ok {
			s.log.Errorf("Skipping vote from Authority %s who failed to reveal", pk)
			continue
		}

		// Epoch is already verified to match the SharedRandomCommit
		// Verify that the voting peer has participated in commit-and-reveal this epoch.
		srv.SetCommit(voteDoc.doc.SharedRandomCommit)
		r := s.reveals[epoch][pk]
		if len(r) != s11n.SharedRandomLength {
			s.log.Errorf("Skipping vote from Authority %v with incorrect Reveal length %d :%v", pk, len(r), r)
			continue
		}
		if !srv.Verify(r) {
			s.log.Errorf("Skipping vote from Authority %v with incorrect Reveal! %v", pk, r)
			continue
		}

		ed := new(eddsa.PublicKey)
		ed.FromBytes(pk[:])
		vote, err := s11n.FromPayload(ed, voteDoc.raw)
		if err != nil {
			s.log.Errorf("Skipping vote from Authority that failed to decode?! %v", err)
			continue
		}
		// serialize the vote parameters and tally these as well.
		params := &config.Parameters{
			MixLambda:       vote.MixLambda,
			MixMaxDelay:     vote.MixMaxDelay,
			SendLambda:      vote.SendLambda,
			SendShift:       vote.SendShift,
			SendMaxInterval: vote.SendMaxInterval,
			DropLambda:      vote.DropLambda,
			DropShift:       vote.DropShift,
			DropMaxInterval: vote.DropMaxInterval,
			LoopLambda:      vote.LoopLambda,
			LoopShift:       vote.LoopShift,
			LoopMaxInterval: vote.LoopMaxInterval,
		}
		b := bytes.Buffer{}
		e := gob.NewEncoder(&b)
		err = e.Encode(params)
		if err != nil {
			s.log.Errorf("Skipping vote from Authority whose MixParameters failed to encode?! %v", err)
			continue
		}
		bs := b.String()
		if _, ok := mixParams[bs]; !ok {
			mixParams[bs] = make([]*s11n.Document, 0)
		}
		mixParams[bs] = append(mixParams[bs], vote)

		// include providers in the tally.
		for _, rawDesc := range vote.Providers {
			k := string(rawDesc)
			if _, ok := mixTally[k]; !ok {
				mixTally[k] = make([]*s11n.Document, 0)
			}
			mixTally[k] = append(mixTally[k], vote)
		}
		// include the rest of the mixes in the tally.
		for _, l := range vote.Topology {
			for _, rawDesc := range l {
				k := string(rawDesc)
				if _, ok := mixTally[k]; !ok {
					mixTally[k] = make([]*s11n.Document, 0)
				}
				mixTally[k] = append(mixTally[k], vote)
			}
		}
	}
	// include mixes that have a threshold of votes
	for rawDesc, votes := range mixTally {
		if len(votes) >= s.threshold {
			// this shouldn't fail as the descriptors have already been verified
			verifier, err := s11n.GetVerifierFromDescriptor([]byte(rawDesc))
			if err != nil {
				return nil, nil, err
			}
			desc, err := s11n.VerifyAndParseDescriptor(verifier, []byte(rawDesc), epoch)
			if err != nil {
				return nil, nil, err
			}
			nodes = append(nodes, &descriptor{desc: desc, raw: []byte(rawDesc)})
		}
	}
	// include parameters that have a threshold of votes
	for bs, votes := range mixParams {
		if len(votes) >= s.threshold {
			params := &config.Parameters{}
			d := gob.NewDecoder(strings.NewReader(bs))
			if err := d.Decode(params); err == nil {
				sortNodesByPublicKey(nodes)
				// successful tally
				return nodes, params, nil
			}
		} else if len(votes) >= s.dissenters {
			return nil, nil, errors.New("Consensus partition?!")
		}

	}
	return nil, nil, errors.New("Consensus failure!")
}

func (s *state) GetConsensus(epoch uint64) (*document, error) {
	s.Lock()
	defer s.Unlock()
	if d := s.documents[epoch]; d != nil {
		return d, nil
	}
	return nil, errNotYet
}

func (s *state) isTabulated(epoch uint64) bool {
	if _, ok := s.documents[epoch]; ok {
		return true
	}
	return false
}

func (s *state) computeSharedRandom(epoch uint64) ([]byte, error) {

	type Reveal struct {
		PublicKey [eddsa.PublicKeySize]byte
		Digest    []byte
	}

	reveals := make([]Reveal, 0)
	srv := sha3.New256()
	srv.Write([]byte("shared-random"))
	srv.Write(epochToBytes(epoch))

	if _, ok := s.votes[epoch]; !ok {
		return nil, fmt.Errorf("authority: No votes present, cannot calculate a shared random for Epoch %d", epoch)
	}
	for pk, vote := range s.votes[epoch] {
		sr := new(SharedRandom)
		if _, ok := s.reveals[epoch][pk]; !ok {
			// skip this vote, authority did not reveal
			continue
		}
		sr.SetCommit(vote.doc.SharedRandomCommit)
		srr := s.reveals[epoch][pk]
		if sr.Verify(srr) {
			reveals = append(reveals, Reveal{pk, srr})
		} else {
			// XXX: failed to verify , log err?
			continue
		}
	}

	sort.Slice(reveals, func(i, j int) bool {
		return string(reveals[i].Digest) > string(reveals[j].Digest)
	})

	for _, reveal := range reveals {
		srv.Write(reveal.PublicKey[:])
		srv.Write(reveal.Digest)
	}
	// XXX: Tor also hashes in the previous srv or 32 bytes of 0x00
	//      How do we bootstrap a new authority?
	zeros := make([]byte, 32)
	if vot, ok := s.documents[s.votingEpoch-1]; ok {
		srv.Write(vot.doc.SharedRandomValue)
	} else {
		srv.Write(zeros)
	}
	return srv.Sum(nil), nil
}

func (s *state) tabulate(epoch uint64) {
	s.log.Noticef("Generating Consensus Document for epoch %v.", epoch)
	// generate the shared random value or fail
	srv, err := s.computeSharedRandom(epoch)
	if err != nil {
		s.log.Warningf("No shared random for epoch %v, aborting!, %v", epoch, err)
		return
	}

	// include all the valid mixes from votes, including our own.
	mixes, params, err := s.tallyVotes(epoch)
	if err != nil {
		s.log.Warningf("No consensus for epoch %v, aborting!, %v", epoch, err)
		return
	}
	s.log.Debug("Mixes tallied, now making a document")
	doc := s.getDocument(mixes, params, srv)

	// Serialize and sign the Document.
	signed, err := s11n.SignDocument(s.s.identityKey, doc)
	if err != nil {
		s.log.Debugf("SignDocument failed with err: %v", err)
		return
	}
	// Save our certificate
	if _, ok := s.certificates[epoch]; !ok {
		s.certificates[epoch] = make(map[[eddsa.PublicKeySize]byte][]byte)
	}
	s.certificates[epoch][s.identityPubKey()] = signed
	if raw, err := cert.GetCertified(signed); err == nil {
		s.log.Debugf("Document for epoch %v saved: %s", epoch, raw)
		s.log.Debugf("sha256(certified): %s", sha256b64(raw))
	}
	// send our vote to the other authorities!
	s.sendVoteToAuthorities([]byte(signed), epoch)
}

func (s *state) generateTopology(nodeList []*descriptor, doc *pki.Document, srv []byte) [][][]byte {
	s.log.Debugf("Generating mix topology.")

	nodeMap := make(map[[constants.NodeIDLength]byte]*descriptor)
	for _, v := range nodeList {
		id := v.desc.IdentityKey.ByteArray()
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
	rng, err := NewDeterministicRandReader(srv[:])
	if err != nil {
		s.log.Errorf("DeterministicRandReader() failed to initialize: %v", err)
		s.s.fatalErrCh <- err
	}
	targetNodesPerLayer := len(nodeList) / s.s.cfg.Debug.Layers
	topology := make([][][]byte, s.s.cfg.Debug.Layers)

	// Assign nodes that still exist up to the target size.
	for layer, nodes := range doc.Topology {
		nodeIndexes := rng.Perm(len(nodes))

		for _, idx := range nodeIndexes {
			if len(topology[layer]) >= targetNodesPerLayer {
				break
			}

			id := nodes[idx].IdentityKey.ByteArray()
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

func (s *state) generateRandomTopology(nodes []*descriptor, srv []byte) [][][]byte {
	s.log.Debugf("Generating random mix topology.")

	// If there is no node history in the form of a previous consensus,
	// then the simplest thing to do is to randomly assign nodes to the
	// various layers.

	if len(srv) != 32 {
		err := errors.New("SharedRandomValue too short")
		s.log.Errorf("srv: %s", srv)
		s.s.fatalErrCh <- err
	}
	rng, err := NewDeterministicRandReader(srv[:])
	if err != nil {
		s.log.Errorf("DeterministicRandReader() failed to initialize: %v", err)
		s.s.fatalErrCh <- err
	}

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
}

func (s *state) isDescriptorAuthorized(desc *pki.MixDescriptor) bool {
	pk := desc.IdentityKey.ByteArray()

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
func (s *state) dupSig(vote commands.Vote) bool {
	if _, ok := s.certificates[s.votingEpoch][vote.PublicKey.ByteArray()]; ok {
		return true
	}
	return false
}
func (s *state) dupVote(vote commands.Vote) bool {
	if _, ok := s.votes[s.votingEpoch][vote.PublicKey.ByteArray()]; ok {
		return true
	}
	return false
}

func (s *state) onRevealUpload(reveal *commands.Reveal) commands.Command {
	s.Lock()
	defer s.Unlock()
	resp := commands.RevealStatus{}
	if reveal.Epoch < s.votingEpoch {
		s.log.Errorf("Received Reveal too early: %d < %d", reveal.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.RevealTooEarly
		return &resp
	}
	if reveal.Epoch > s.votingEpoch {
		s.log.Errorf("Received Reveal too late: %d > %d", reveal.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.RevealTooLate
		return &resp
	}
	// if already revealed
	_, ok := s.authorizedAuthorities[reveal.PublicKey.ByteArray()]
	if !ok {
		s.log.Error("Voter not white-listed.")
		resp.ErrorCode = commands.RevealNotAuthorized
		return &resp
	}

	// haven't received a vote yet for this epoch
	if _, ok := s.votes[s.votingEpoch]; !ok {
		s.log.Error("Reveal received before any votes!?.")
		resp.ErrorCode = commands.RevealTooEarly
		return &resp
	}
	// haven't received a vote from this peer yet for this epoch
	if _, ok := s.votes[s.votingEpoch][reveal.PublicKey.ByteArray()]; !ok {
		s.log.Error("Reveal received before peer's vote?.")
		resp.ErrorCode = commands.RevealTooEarly
		return &resp
	}

	// the first reveal received this round
	if _, ok := s.reveals[s.votingEpoch]; !ok {
		s.reveals[s.votingEpoch] = make(map[[eddsa.PublicKeySize]byte][]byte)
	}

	// already received a reveal for this round
	if _, ok := s.reveals[s.votingEpoch][reveal.PublicKey.ByteArray()]; ok {
		s.log.Error("Another Reveal received from peer's vote?.")
		resp.ErrorCode = commands.RevealAlreadyReceived
		return &resp
	}

	r := make([]byte, 0)
	r = append(r, epochToBytes(s.votingEpoch)...)
	r = append(r, reveal.Digest[:]...)
	s.log.Debug("Reveal OK.")
	s.reveals[s.votingEpoch][reveal.PublicKey.ByteArray()] = r
	resp.ErrorCode = commands.RevealOk
	return &resp

}

func (s *state) onVoteUpload(vote *commands.Vote) commands.Command {
	s.Lock()
	defer s.Unlock()
	resp := commands.VoteStatus{}

	if vote.Epoch < s.votingEpoch {
		s.log.Errorf("Received Vote too early: %d < %d", vote.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.VoteTooEarly
		return &resp
	}
	if vote.Epoch > s.votingEpoch {
		s.log.Errorf("Received Vote too late: %d > %d", vote.Epoch, s.votingEpoch)
		resp.ErrorCode = commands.VoteTooLate
		return &resp
	}
	_, ok := s.authorizedAuthorities[vote.PublicKey.ByteArray()]
	if !ok {
		s.log.Error("Voter not white-listed.")
		resp.ErrorCode = commands.VoteNotAuthorized
		return &resp
	}

	doc, _, err := s11n.VerifyAndParseDocument(vote.Payload, vote.PublicKey)
	if err != nil {
		s.log.Error("Vote failed signature verification.")
		resp.ErrorCode = commands.VoteNotSigned
		return &resp
	}

	// haven't received a vote yet for this epoch
	if _, ok := s.votes[s.votingEpoch]; !ok {
		s.votes[s.votingEpoch] = make(map[[eddsa.PublicKeySize]byte]*document)
	}
	// haven't received a certificate yet for this epoch
	if _, ok := s.certificates[s.votingEpoch]; !ok {
		s.certificates[s.votingEpoch] = make(map[[eddsa.PublicKeySize]byte][]byte)
	}
	// peer has not yet voted for this epoch
	if !s.dupVote(*vote) {
		s.votes[s.votingEpoch][vote.PublicKey.ByteArray()] = &document{
			raw: vote.Payload,
			doc: doc,
		}
		s.log.Debug("Vote OK.")
		resp.ErrorCode = commands.VoteOk
	} else {
		// peer has voted previously, and has not yet submitted a signature
		if !s.dupSig(*vote) {
			s.certificates[s.votingEpoch][vote.PublicKey.ByteArray()] = vote.Payload
			if raw, err := cert.GetCertified(vote.Payload); err == nil {
				s.log.Debugf("Certificate for epoch %v saved: %s", vote.Epoch, raw)
				s.log.Debugf("sha256(certified): %s", sha256b64(raw))
			}
			resp.ErrorCode = commands.VoteOk
			return &resp
		}
		// peer is behaving strangely
		// error; two votes from same peer
		s.log.Error("Vote command invalid: more than one vote from same peer is not allowed.")
		resp.ErrorCode = commands.VoteAlreadyReceived
		return &resp
	}
	return &resp
}

func (s *state) onDescriptorUpload(rawDesc []byte, desc *pki.MixDescriptor, epoch uint64) error {
	s.Lock()
	defer s.Unlock()

	// Note: Caller ensures that the epoch is the current epoch +- 1.
	pk := desc.IdentityKey.ByteArray()

	// Get the public key -> descriptor map for the epoch.
	m, ok := s.descriptors[epoch]
	if !ok {
		m = make(map[[eddsa.PublicKeySize]byte]*descriptor)
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

	id := base64.StdEncoding.EncodeToString(desc.IdentityKey.Bytes())
	s.log.Debugf("Node %s: Sucessfully submitted descriptor for epoch %v.", id, epoch)
	s.onUpdate()
	return nil
}

func (s *state) documentForEpoch(epoch uint64) ([]byte, error) {
	//const generationDeadline = 45 * time.Minute
	var generationDeadline = 7 * epochtime.Period / 8

	s.RLock()
	defer s.RUnlock()

	// If we have a serialized document, return it.
	if d, ok := s.documents[epoch]; ok {
		return d.raw, nil
	}

	// Otherwise, return an error based on the time.
	now, _, till := epochtime.Now()
	switch epoch {
	case now:
		// Check to see if we are doing a bootstrap, and it's possible that
		// we may decide to publish a document at some point ignoring the
		// standard schedule.
		if now == s.votingEpoch {
			return nil, errNotYet
		}

		// We missed the deadline to publish a descriptor for the current
		// epoch, so we will never be able to service this request.
		return nil, errGone
	case now + 1:
		// If it's past the time by which we should have generated a document
		// then we will never be able to service this.
		if till < generationDeadline {
			return nil, errGone
		}
		return nil, errNotYet
	default:
		if epoch < now {
			// Requested epoch is in the past, and it's not in the cache.
			// We will never be able to satisfy this request.
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
					_, good, _, err := cert.VerifyThreshold(s.verifiers, s.threshold, rawDoc)
					if err != nil {
						s.log.Errorf("Failed to verify threshold on restored document")
						break // or continue?
					}
					doc, _, err := s11n.VerifyAndParseDocument(rawDoc, good[0])
					if err != nil {
						s.log.Errorf("Failed to validate persisted document: %v", err)
					} else if doc.Epoch != epoch {
						// The document for the wrong epoch was persisted?
						s.log.Errorf("Persisted document has unexpected epoch: %v", doc.Epoch)
					} else {
						s.log.Debugf("Restored Document for epoch %v: %v.", epoch, doc)
						d := new(document)
						d.doc = doc
						d.raw = rawDoc
						s.documents[epoch] = d
					}
				}

				eDescsBkt := descsBkt.Bucket(k)
				if eDescsBkt == nil {
					s.log.Debugf("No persisted Descriptors for epoch: %v.", epoch)
					continue
				}

				c := eDescsBkt.Cursor()
				for pk, rawDesc := c.First(); pk != nil; pk, rawDesc = c.Next() {
					verifier, err := s11n.GetVerifierFromDescriptor([]byte(rawDesc))
					if err != nil {
						return err
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

					m, ok := s.descriptors[epoch]
					if !ok {
						m = make(map[[eddsa.PublicKeySize]byte]*descriptor)
						s.descriptors[epoch] = m
					}

					d := new(descriptor)
					d.desc = desc
					d.raw = rawDesc
					m[desc.IdentityKey.ByteArray()] = d

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

	// set voting schedule at runtime
	mixPublishDeadline = epochtime.Period / 2
	authorityVoteDeadline = mixPublishDeadline + epochtime.Period/8
	authorityRevealDeadline = authorityVoteDeadline + epochtime.Period/8
	publishConsensusDeadline = authorityRevealDeadline + epochtime.Period/8

	st.log.Debugf("State initialized with epoch Period: %s", epochtime.Period)
	st.log.Debugf("State initialized with mixPublishDeadline: %s", mixPublishDeadline)
	st.log.Debugf("State initialized with authorityVoteDeadline: %s", authorityVoteDeadline)
	st.log.Debugf("State initialized with authorityRevealDeadline: %s", authorityRevealDeadline)
	st.log.Debugf("State initialized with publishConsensusDeadline: %s", publishConsensusDeadline)
	st.verifiers = make([]cert.Verifier, len(s.cfg.Authorities)+1)
	for i, auth := range s.cfg.Authorities {
		st.verifiers[i] = cert.Verifier(auth.IdentityPublicKey)
	}
	st.verifiers[len(s.cfg.Authorities)] = cert.Verifier(s.IdentityKey())
	st.threshold = len(s.cfg.Authorities) / 2
	st.dissenters = len(s.cfg.Authorities)/2 - 1

	// Initialize the authorized peer tables.
	st.authorizedMixes = make(map[[eddsa.PublicKeySize]byte]bool)
	for _, v := range st.s.cfg.Mixes {
		pk := v.IdentityKey.ByteArray()
		st.authorizedMixes[pk] = true
	}
	st.authorizedProviders = make(map[[eddsa.PublicKeySize]byte]string)
	for _, v := range st.s.cfg.Providers {
		pk := v.IdentityKey.ByteArray()
		st.authorizedProviders[pk] = v.Identifier
	}
	st.authorizedAuthorities = make(map[[eddsa.PublicKeySize]byte]bool)
	for _, v := range st.s.cfg.Authorities {
		pk := v.IdentityPublicKey.ByteArray()
		st.authorizedAuthorities[pk] = true
	}

	st.documents = make(map[uint64]*document)
	st.descriptors = make(map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor)
	st.votes = make(map[uint64]map[[eddsa.PublicKeySize]byte]*document)
	st.certificates = make(map[uint64]map[[eddsa.PublicKeySize]byte][]byte)
	st.reveals = make(map[uint64]map[[eddsa.PublicKeySize]byte][]byte)

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
	epoch, _, till := epochtime.Now()
	if till < 1*time.Minute {
		epoch++
	}
	if _, ok := st.documents[epoch]; !ok {
		st.votingEpoch = epoch
		st.state = stateBootstrap
	}

	st.Go(st.worker)
	return st, nil
}

func (s *state) backgroundFetchConsensus(epoch uint64) {
	// lock must already be held!
	// If there isn't a consensus for the previous epoch, ask the other
	// authorities for a consensus.
	_, ok := s.documents[epoch]
	if !ok {
		go func() {
			cfg := &client.Config{s.s.logBackend, s.s.cfg.Authorities, nil}
			c, err := client.New(cfg)
			if err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
			defer cancel()
			doc, rawDoc, err := c.Get(ctx, epoch)
			if err != nil {
				return
			}
			s.Lock()
			defer s.Unlock()

			// It's possible that the state has changed
			// if backgroundFetchConsensus was called
			// multiple times during bootstrapping
			if _, ok := s.documents[epoch]; !ok {
				s.documents[epoch] = &document{doc, rawDoc}
			}
		}()
	}
}

func epochToBytes(e uint64) []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, e)
	return ret
}

func sortNodesByPublicKey(nodes []*descriptor) {
	dTos := func(d *descriptor) string {
		pk := d.desc.IdentityKey.ByteArray()
		return string(pk[:])
	}
	sort.Slice(nodes, func(i, j int) bool { return dTos(nodes[i]) < dTos(nodes[j]) })
}

func sha256b64(raw []byte) string {
	var hash [32]byte = sha3.Sum256(raw)
	return base64.StdEncoding.EncodeToString(hash[:])
}
