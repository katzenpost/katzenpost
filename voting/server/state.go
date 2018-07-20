// state.go - Katzenpost non-voting authority server state.
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
	"github.com/katzenpost/authority/voting/internal/s11n"
	"github.com/katzenpost/authority/voting/server/config"
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
	"gopkg.in/square/go-jose.v2"
)

const (
	descriptorsBucket        = "descriptors"
	documentsBucket          = "documents"
	publishDeadline          = 3600 * time.Second
	mixPublishDeadline       = 2 * time.Hour
	authorityVoteDeadline    = 2*time.Hour + 7*time.Minute + 30*time.Second
	authorityRevealDeadline  = 2*time.Hour + 10*time.Minute
	publishConsensusDeadline = 2*time.Hour + 15*time.Minute
	stateAcceptDescriptor    = "accept_desc"
	stateAcceptVote          = "accept_vote"
	stateAcceptReveal        = "accept_reveal"
	stateAcceptSignature     = "accept_signature"
	stateConsensed           = "got_consensus"
	stateConsensusFailed     = "failed_consensus"
)

var (
	errGone   = errors.New("authority: Requested epoch will never get a Document")
	errNotYet = errors.New("authority: Document is not ready yet")
)

type descriptor struct {
	desc *pki.MixDescriptor
	raw  []byte
}

type document struct {
	doc *pki.Document
	raw []byte
}

func (d *document) getSignatures() ([]jose.Signature, error) {
	if d.raw != nil && d.doc != nil {
		signed, err := jose.ParseSigned(string(d.raw))
		if err != nil {
			return nil, err
		}
		return signed.Signatures, nil
	}
	return nil, errors.New("document getSignatures failure: struct type not initialized")
}

func (d *document) addSig(publicKey *eddsa.PublicKey, sig *jose.Signature) error {
	// caller MUST verify that the signer is authorized
	// this function only verifies that the signature
	// is valid and not duplicated.
	signed, err := jose.ParseSigned(string(d.raw))
	// verify the signature hasn't already been added
	if len(signed.Signatures) != 0 {
		for _, v := range signed.Signatures {
			if bytes.Equal(v.Signature, sig.Signature) {
				return fmt.Errorf("already attached signature")
			}
		}
	}
	// verify that the signature signs the document
	signed.Signatures = append(signed.Signatures, *sig)
	_, _, _, err = signed.VerifyMulti(*publicKey.InternalPtr())
	if err == nil {
		// update object
		d.raw = []byte(signed.FullSerialize())
	}
	return err
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

	documents   map[uint64]*document
	descriptors map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor
	votes       map[uint64]map[[eddsa.PublicKeySize]byte]*document
	reveals     map[uint64]map[[eddsa.PublicKeySize]byte][]byte
	signatures  map[uint64]map[[eddsa.PublicKeySize]byte]*jose.Signature

	updateCh       chan interface{}
	bootstrapEpoch uint64

	votingEpoch uint64
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
		case <-s.fsmWakeup():
			s.log.Debugf("authority: Wakeup due to voting schedule.")
		}
		s.fsm()
	}
}

func (s *state) fsmWakeup() <-chan time.Time {
	s.Lock()
	defer s.Unlock()

	_, elapsed, next_epoch := epochtime.Now()
	// if we're bootstrapping, hurry things up
	if s.doBootstrap() {
		s.log.Debugf("authority: Bootstrapping, hurrying things up...")
		return time.After(10 * time.Second)
	}

	switch {
	case s.state == stateConsensed:
		s.log.Debugf("authority: Consensus reached, next wakeup at %s", next_epoch)
		return time.After(next_epoch)
	case s.state == stateConsensusFailed:
		s.log.Debugf("authority: Consensus failed, next wakeup at %s", next_epoch)
		return time.After(next_epoch)
	case s.state == stateAcceptDescriptor:
		return time.After(mixPublishDeadline - elapsed)
	case s.state == stateAcceptVote:
		return time.After(authorityVoteDeadline - elapsed)
	case s.state == stateAcceptReveal:
		return time.After(authorityRevealDeadline - elapsed)
	case s.state == stateAcceptSignature:
		return time.After(publishConsensusDeadline - elapsed)
	default:
		return time.After(next_epoch)
	}
}

func (s *state) fsm() {
	s.Lock()
	defer s.Unlock()
	switch {
	case s.state == stateAcceptDescriptor:
		if !s.hasEnoughDescriptors(s.descriptors[s.votingEpoch]) {
			s.log.Debugf("Not voting because insufficient descriptors uploaded!")
			break
		} else {
			if !s.voted(s.votingEpoch) {
				s.log.Debugf("Voting for epoch %v", s.votingEpoch)
				s.vote(s.votingEpoch)
			}
		}
		s.state = stateAcceptVote
	case s.state == stateAcceptVote:
		s.state = stateAcceptReveal
	case s.state == stateAcceptReveal:
		// we have collect all of the reveal values
		// now we compute the shared random value
		// and produce a consensus from votes
		if !s.isTabulated(s.votingEpoch) {
			s.log.Debugf("Tabulating for epoch %v", s.votingEpoch)
			s.tabulate(s.votingEpoch)
		}
		s.state = stateAcceptSignature
	case s.state == stateAcceptSignature:
		s.state = stateConsensusFailed
		if !s.hasConsensus(s.votingEpoch) {
			s.log.Debugf("Combining signatures for epoch %v", s.votingEpoch)
			s.combine(s.votingEpoch)
			if s.hasConsensus(s.votingEpoch) {
				s.state = stateConsensed
				s.votingEpoch = s.votingEpoch + 1
				s.log.Debugf("Updated votingEpoch to %v", s.votingEpoch)
			} else {
				// Failed to make consensus while bootstrapping, try try again.
				if s.doBootstrap() {
					delete(s.documents, s.votingEpoch)
					delete(s.reveals, s.votingEpoch)
					delete(s.descriptors, s.votingEpoch)
					delete(s.votes, s.votingEpoch)
					delete(s.descriptors, s.votingEpoch)
				}
			}
		}
	default:
		s.state = stateAcceptDescriptor
	}
	s.log.Debugf("authority: FSM in state %v", s.state)
	s.pruneDocuments()
}

func (s *state) doBootstrap() bool {
	// lock must already be held!
	epoch, _, _ := epochtime.Now()

	// If we are doing a bootstrap, and we don't have a document, attempt
	// to generate one for the current epoch regardless of the time.
	if epoch == s.bootstrapEpoch && !s.hasConsensus(epoch) {
		return true
	}
	return false
}

func (s *state) combine(epoch uint64) {
	// count up the signatures we've got
	doc, ok := s.documents[epoch]
	if !ok {
		// consensus failed
		s.log.Debugf("What, no preconsensus yet??")
		return
	}
	for pk, sig := range s.signatures[epoch] {
		ed := new(eddsa.PublicKey)
		ed.FromBytes(pk[:])
		err := doc.addSig(ed, sig)
		if err != nil {
			s.log.Errorf("Signature failed to validate: %v", err)
		}
	}

	if !s.hasConsensus(epoch) {
		s.log.Debugf("No consensus for epoch %v", epoch)
		// if we're bootstrapping, clear state and try try again
		// this is helpful because authorities probably will
		// not startup within the state-transition time
		if epoch == s.bootstrapEpoch {
			delete(s.documents, epoch)
			delete(s.signatures, epoch)
			delete(s.votes, epoch)
		}
	} else {
		s.log.Debugf("Consensus made for epoch %v", epoch)
		// XXX: save consensus to disk!
	}
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
	//if d, ok := s.documents[s.votingEpoch-1]; ok {
	//	topology = s.generateTopology(nodes, d.doc)
	//} else {
	//	topology = s.generateRandomTopology(nodes)
	//}
	topology = s.generateRandomTopology(nodes, srv)

	// Build the Document.
	doc := &s11n.Document{
		Epoch:           s.votingEpoch,
		MixLambda:       params.MixLambda,
		MixMaxDelay:     params.MixMaxDelay,
		SendLambda:      params.SendLambda,
		SendShift:       params.SendShift,
		SendMaxInterval: params.SendMaxInterval,
		Topology:        topology,
		Providers:       providers,
	}
	return doc
}

type SRV struct {
	epoch  uint64
	commit []byte
	reveal []byte
}

// TODO: update the s11n document type to contain a slice of srv values
// compute the actual shared random number from a list of verified srv values
// figure out how to include the server identity keys because the committed values must be sorted
// what happens if reveals are not broadcast to the rest of authorities?

func (s *SRV) Commit(epoch uint64) []byte {
	// pick a random number
	// COMMIT = base64-encode( TIMESTAMP || H(REVEAL) )
	// REVEAL = base64-encode( TIMESTAMP || H(RN) )
	rn := make([]byte, 0, 32)
	io.ReadFull(rand.Reader, rn)
	s.commit = make([]byte, 8, 40)
	s.reveal = make([]byte, 8, 40)
	binary.BigEndian.PutUint64(s.reveal, epoch)
	binary.BigEndian.PutUint64(s.commit, epoch)
	reveal := sha3.Sum256(rn)
	copy(s.reveal[8:], reveal[:])
	//for i := 0; i < len(reveal); i++ {
	//	s.reveal[8+i] = reveal[i]
	//}
	commit := sha3.Sum256(s.reveal)
	copy(s.commit[8:], commit[:])
	//for i := 0; i < len(commit); i++ {
	//	s.commit[8+i] = commit[i]
	//}
	return s.commit
}

func (s *SRV) GetCommit() []byte {
	return s.commit
}

func (s *SRV) SetCommit(rawCommit []byte) {
	s.epoch = binary.BigEndian.Uint64(rawCommit)
	copy(s.commit, rawCommit)
}

func (s *SRV) Verify(reveal []byte) bool {
	if len(reveal) != 40 {
		return false
	}
	epoch := binary.BigEndian.Uint64(reveal[0:8])
	allegedCommit := sha3.Sum256(reveal)
	if epoch == s.epoch && bytes.Equal(s.commit, allegedCommit[:]) {
		return true
	}
	return false
}

func (s *SRV) Reveal() []byte {
	return s.reveal
}

func (s *state) vote(epoch uint64) {
	descriptors := []*descriptor{}
	for _, desc := range s.descriptors[epoch] {
		descriptors = append(descriptors, desc)
	}
	srv := new(SRV)
	commit := srv.Commit(epoch)
	vote := s.getDocument(descriptors, s.s.cfg.Parameters, commit)
	vote.SRVCommit = commit
	signedVote := s.sign(vote)
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
	// we're holding a lock so better run this in another thread
	go s.sendVoteToAuthorities(signedVote.raw)
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

func (s *state) sendVoteToPeer(peer *config.AuthorityPeer, vote []byte) error {
	// get a connector here
	conn, err := net.Dial("tcp", peer.Addresses[0]) // XXX
	if err != nil {
		return err
	}
	defer conn.Close()
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
		Epoch:     s.votingEpoch,
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

// sendVoteToAuthorities sends s.descriptors[epoch] to
// all Directory Authorities
func (s *state) sendVoteToAuthorities(vote []byte) {
	// Lock is held (called from the onWakeup hook).

	s.log.Noticef("Sending Document for epoch %v, to all Directory Authorities.", s.votingEpoch)

	for _, peer := range s.s.cfg.Authorities {
		err := s.sendVoteToPeer(peer, vote)
		if err != nil {
			s.log.Error("failed to send vote to peer %v", peer)
		}
	}
}

func (s *state) tallyVotes(epoch uint64) ([]*descriptor, *config.Parameters, error) {
	// Lock is held (called from the onWakeup hook).
	_, ok := s.votes[epoch]
	if !ok {
		return nil, nil, errors.New(fmt.Sprintf("No votes for epoch %v!", epoch))
	}
	if len(s.votes[epoch]) <= s.threshold {
		return nil, nil, errors.New(fmt.Sprintf("Not enough votes for epoch %v!", epoch))
	}

	nodes := make([]*descriptor, 0)
	mixTally := make(map[string][]*s11n.Document)
	mixParams := make(map[string][]*s11n.Document)
	srv := new(SRV)
	for pk, voteDoc := range s.votes[epoch] {
		// Parse the payload bytes into the s11n.Document
		// so that we can access the mix descriptors + sigs
		// The votes have already been validated.

		if _, ok := s.reveals[epoch][pk]; !ok {
			s.log.Errorf("Skipping vote from Authority %v who failed to reveal", pk)
			continue
		}

		// Epoch is already verified to maatch the SRVCommit
		srv.SetCommit(voteDoc.doc.SRVCommit)
		if !srv.Verify(s.reveals[epoch][pk]) {
			s.log.Errorf("Skipping vote from Authority %v with incorrect Reveal!", pk)
			continue
		}

		ed := new(eddsa.PublicKey)
		ed.FromBytes(pk[:])
		vote, err := s11n.FromPayload(*ed.InternalPtr(), voteDoc.raw)
		if err != nil {
			s.log.Errorf("Vote from Authority failed to decode?! %v", err)
			break
		}
		params := &config.Parameters{
			MixLambda:       vote.MixLambda,
			MixMaxDelay:     vote.MixMaxDelay,
			SendLambda:      vote.SendLambda,
			SendShift:       vote.SendShift,
			SendMaxInterval: vote.SendMaxInterval,
		}
		b := bytes.Buffer{}
		e := gob.NewEncoder(&b)
		err = e.Encode(params)
		if err != nil {
			s.log.Errorf("MixParameters in Vote from Authority failed to encode?! %v", err)
		}
		bs := b.String()
		if _, ok := mixParams[bs]; !ok {
			mixParams[bs] = make([]*s11n.Document, 0)
		}
		mixParams[bs] = append(mixParams[bs], vote)

		for _, rawDesc := range vote.Providers {
			k := string(rawDesc)
			if _, ok := mixTally[k]; !ok {
				mixTally[k] = make([]*s11n.Document, 0)
			}
			mixTally[k] = append(mixTally[k], vote)
		}
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
	for rawDesc, votes := range mixTally {
		if len(votes) > s.threshold {
			// this shouldn't fail as the descriptors have already been verified
			if desc, err := s11n.VerifyAndParseDescriptor([]byte(rawDesc), epoch); err == nil {
				nodes = append(nodes, &descriptor{desc: desc, raw: []byte(rawDesc)})
			}
		} else if len(votes) >= s.dissenters {
			return nil, nil, errors.New("Consensus failure!")
		}
	}
	for bs, votes := range mixParams {
		if len(votes) > s.threshold {
			params := &config.Parameters{}
			d := gob.NewDecoder(strings.NewReader(bs))
			if err := d.Decode(params); err == nil {
				sortNodesByPublicKey(nodes)
				return nodes, params, nil
			}
		} else if len(votes) >= s.dissenters {
			return nil, nil, errors.New("Consensus partition?!")
		}

	}
	return nil, nil, errors.New("Consensus failure!")
}

func (s *state) GetConsensus(epoch uint64) (*document, error) {
	// Lock is held (called from the onWakeup hook).
	// already have consensus for this epoch
	if s.hasConsensus(epoch) {
		return s.documents[epoch], nil
	}
	return nil, errNotYet
}

func (s *state) isTabulated(epoch uint64) bool {
	if _, ok := s.documents[epoch]; ok {
		return true
	}
	return false
}

func (s *state) computeSRV(epoch uint64) []byte {

	type Reveal struct {
		PublicKey [eddsa.PublicKeySize]byte
		Digest    []byte
	}

	reveals := make([]Reveal, 0)
	srv := sha3.New256()
	srv.Write([]byte("shared-random"))
	srv.Write(epochToBytes(epoch))

	sr := new(SRV)
	for pk, vote := range s.votes[epoch] {
		if _, ok := s.reveals[epoch][pk]; !ok {
			// skip this vote, authority did not reveal
			continue
		}
		sr.SetCommit(vote.doc.SRVCommit)
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
		srv.Write(vot.doc.SRValue)
	} else {
		srv.Write(zeros)
	}
	digest := make([]byte, 0, 32)
	srv.Sum(digest)
	return digest
}

func (s *state) tabulate(epoch uint64) {
	s.log.Noticef("Generating Consensus Document for epoch %v.", epoch)
	// generate the shared random value
	srv := s.computeSRV(epoch)

	// include all the valid mixes from votes, including our own.
	mixes, params, err := s.tallyVotes(epoch)
	if err != nil {
		s.log.Warningf("No consensus for epoch %v, aborting!, %v", epoch, err)
		return
	}
	s.log.Debug("Mixes tallied, now making a document")
	doc := s.getDocument(mixes, params, srv[:])

	// Serialize and sign the Document.
	// XXX s.signatures[epoch] might already be populated
	// which means we might be voting with a multisig document.
	// this isn't a problem because we extract the signature from
	// the document and should be signing the same thing
	signed, err := s11n.MultiSignDocument(s.s.identityKey, nil, doc)
	if err != nil {
		// This should basically always succeed.
		s.log.Errorf("Failed to sign document: %v", err)
		s.s.fatalErrCh <- err
		return
	}

	// Ensure the document is sane.
	pDoc, _, err := s11n.VerifyAndParseDocument([]byte(signed), s.s.identityKey.PublicKey())
	if err != nil {
		// This should basically always succeed.
		s.log.Errorf("Signed document failed validation: %v", err)
		s.s.fatalErrCh <- err
		return
	}
	// save the document
	d := &document{doc: pDoc, raw: []byte(signed)}
	if _, ok := s.documents[epoch]; !ok {
		s.log.Debugf("Document for epoch %v saved!", epoch)
		s.documents[epoch] = d
	}

	// send our vote to the other authorities!
	go s.sendVoteToAuthorities([]byte(signed))
}

func (s *state) hasConsensus(epoch uint64) bool {
	doc, ok := s.documents[epoch]
	if !ok {
		return false
	}
	sigMap, err := s11n.VerifyPeerMulti(doc.raw, s.s.cfg.Authorities)
	// +1 because s.s.cfg.Authorities does not include our key,
	// though we have already verified that our signature is valid
	if err == nil && len(sigMap)+1 > s.threshold {
		return true
	}
	if err != nil {
		s.log.Debugf("VerifyPeerMulti failed: %v", err)
	}
	if len(sigMap) <= s.threshold {
		s.log.Debugf("Less signatures than needed: %v", len(sigMap))
	}
	return false
}

func (s *state) generateTopology(nodeList []*descriptor, doc *pki.Document) [][][]byte {
	s.log.Debugf("Generating mix topology.")

	nodeMap := make(map[[constants.NodeIDLength]byte]*descriptor)
	for _, v := range nodeList {
		id := v.desc.IdentityKey.ByteArray()
		nodeMap[id] = v
	}

	// Since there is an existing network topology, use that as the basis for
	// generating the mix topology such that the number of nodes per layer is
	// approximately equal, and as many nodes as possible retain their existing
	// layer assignment to minimise network churn.
	// TODO: shared random
	key := [32]byte{0x42}
	rng, err := NewDeterministicRandReader(key[:])
	if err != nil {
		s.log.Errorf("DeterministicRandReader() failed to initialize: %v", err)
		s.s.fatalErrCh <- err
	}
	targetNodesPerLayer := len(nodeList) / s.s.cfg.Debug.Layers
	topology := make([][][]byte, s.s.cfg.Debug.Layers)

	// Assign nodes that still exist up to the target size.
	for layer, nodes := range doc.Topology {
		//nodeIndexes := rng.Perm(len(nodes))
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

	rng, err := NewDeterministicRandReader(srv)
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
	for e := range s.signatures {
		if e < cmpEpoch {
			delete(s.descriptors, e)
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
	if _, ok := s.signatures[s.votingEpoch][vote.PublicKey.ByteArray()]; ok {
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
		s.log.Errorf("Received Vote too late: %d > %d", reveal.Epoch, s.votingEpoch)
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
		resp.ErrorCode = commands.RevealTooSoon
		return &resp
	}
	// haven't received a vote from this peer yet for this epoch
	if _, ok := s.votes[s.votingEpoch][reveal.PublicKey.ByteArray()]; !ok {
		s.log.Error("Reveal received before peer's vote?.")
		resp.ErrorCode = commands.RevealTooSoon
		return &resp
	}

	// the first reveal received this round
	if _, ok := s.reveals[s.votingEpoch]; !ok {
		s.votes[s.votingEpoch] = make(map[[eddsa.PublicKeySize]byte]*document)
	}

	// already received a reveal for this round
	if _, ok := s.reveals[s.votingEpoch][reveal.PublicKey.ByteArray()]; ok {
		s.log.Error("Another Reveal received from peer's vote?.")
		resp.ErrorCode = commands.RevealAlreadyReceived
		return &resp
	}

	s.reveals[s.votingEpoch][reveal.PublicKey.ByteArray()] = reveal.Digest[:]
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
	// haven't received a signature yet for this epoch
	if _, ok := s.signatures[s.votingEpoch]; !ok {
		s.signatures[s.votingEpoch] = make(map[[eddsa.PublicKeySize]byte]*jose.Signature)
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
			// this was already verified by s11n.VerifyAndParseDocument(...)
			// but we want to extract the signature from the payload
			signed, err := jose.ParseSigned(string(vote.Payload))
			if err != nil {
				s.log.Errorf("onVoteUpload vote parse failure: %s", err)
				resp.ErrorCode = commands.VoteNotSigned
				return &resp
			}
			index, sig, _, err := signed.VerifyMulti(*vote.PublicKey.InternalPtr())
			if err != nil || index != 0 {
				s.log.Errorf("onVoteUpload signature parse failure: %s", err)
				resp.ErrorCode = commands.VoteNotSigned
				return &resp
			}

			s.log.Debugf("Signature OK.")
			s.signatures[s.votingEpoch][vote.PublicKey.ByteArray()] = &sig
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

	s.log.Debugf("Node %v: Sucessfully submitted descriptor for epoch %v.", desc.IdentityKey, epoch)
	s.onUpdate()
	return nil
}

func (s *state) documentForEpoch(epoch uint64) ([]byte, error) {
	const generationDeadline = 45 * time.Minute

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
		if now == s.bootstrapEpoch {
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
					if doc, _, err := s11n.VerifyAndParseDocument(rawDoc, s.s.identityKey.PublicKey()); err != nil {
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
					desc, err := s11n.VerifyAndParseDescriptor(rawDesc, epoch)
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
	st.updateCh = make(chan interface{}, 1) // Buffered!
	st.threshold = len(st.s.cfg.Authorities)/2 + 1
	// how many invalid signatures from other peers before breaking consensus
	st.dissenters = len(st.s.cfg.Authorities)/2 - 1

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
	st.signatures = make(map[uint64]map[[eddsa.PublicKeySize]byte]*jose.Signature)
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
	epoch, _, _ := epochtime.Now()
	if _, ok := st.documents[epoch]; !ok {
		st.bootstrapEpoch = epoch
		st.votingEpoch = epoch
		st.state = stateAcceptDescriptor
	}

	st.Go(st.worker)
	return st, nil
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
