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
	"path/filepath"
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
	"gopkg.in/op/go-logging.v1"
	"gopkg.in/square/go-jose.v2"
)

const (
	descriptorsBucket = "descriptors"
	documentsBucket   = "documents"
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

func (d *document) addSig(sig *jose.Signature) error {
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
	_, _, _, err = signed.VerifyMulti(sig)
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
	signatures  map[uint64]map[[eddsa.PublicKeySize]byte]*jose.Signature

	updateCh       chan interface{}
	bootstrapEpoch uint64

	votingEpoch uint64
	threshold   int
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
	const wakeInterval = 60 * time.Second

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
	const publishDeadline = 3600 * time.Second
	const mixPublishDeadline = 2 * time.Hour
	const authorityVoteDeadline = 2*time.Hour + 7*time.Minute + 30*time.Second
	const publishConsensusDeadline = 2*time.Hour + 15*time.Minute
	epoch, elapsed, _ := epochtime.Now()

	s.Lock()
	defer s.Unlock()

	// If we are doing a bootstrap, and we don't have a document, attempt
	// to generate one for the current epoch regardless of the time.
	if epoch == s.bootstrapEpoch && s.documents[epoch] == nil {
		// The bootstrap phase will belatedly generate a document for
		// the current epoch iff it receives descriptor uploads for *ALL*
		// nodes it knows about (eg: Test setups).
		nrBootstrapDescs := len(s.authorizedMixes) + len(s.authorizedProviders)
		if m, ok := s.descriptors[epoch]; ok && len(m) == nrBootstrapDescs {
			// XXX FIX ME
		}
	}
	// If it is past the descriptor upload period and we have yet to generate a
	// document for the *next* epoch, generate a document and send it to all
	// of the other Directory Authorities.
	if elapsed > mixPublishDeadline && elapsed < authorityVoteDeadline {
		if !s.voted(s.votingEpoch) {
			s.vote(s.votingEpoch)
		}
	}
	// If it is now past the voting deadline, and before the consensus
	// has been published, send a signature to the other authorities
	// of the document this authority believes will be the consensus
	if elapsed > authorityVoteDeadline && elapsed < publishConsensusDeadline {
		if !s.isTabulated(s.votingEpoch) {
			s.tabulate(s.votingEpoch)
		}
	}
	// we should now have received enough signatures to make consensus.
	if elapsed > publishConsensusDeadline {
		// XXX do this once, not repeatedly until consensus is reached or next epoch
		if !s.hasConsensus(s.votingEpoch) {
			s.combine(s.votingEpoch)
		}
	}
	// Purge overly stale documents.
	s.pruneDocuments()
}

func (s *state) combine(epoch uint64) {
	// count up the signatures we've got
	doc, ok := s.documents[epoch]
	if !ok {
		// consensus failed
		return
	}
	for _, sig := range s.signatures[s.votingEpoch] {
		doc.addSig(sig)
	}
	if !s.hasConsensus(epoch) {
		// XXX we don't have a consensus! OH NOES!
		delete(s.documents, epoch) // XXX: really?
	} else {
		// save consensus to disk
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

func (s *state) getDocument(descriptors []*descriptor) *s11n.Document {
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
	if d, ok := s.documents[s.votingEpoch-1]; ok {
		topology = s.generateTopology(nodes, d.doc)
	} else {
		topology = s.generateRandomTopology(nodes)
	}

	// Build the Document.
	doc := &s11n.Document{
		Epoch:           s.votingEpoch,
		MixLambda:       s.s.cfg.Parameters.MixLambda,
		MixMaxDelay:     s.s.cfg.Parameters.MixMaxDelay,
		SendLambda:      s.s.cfg.Parameters.SendLambda,
		SendShift:       s.s.cfg.Parameters.SendShift,
		SendMaxInterval: s.s.cfg.Parameters.SendMaxInterval,
		Topology:        topology,
		Providers:       providers,
	}
	return doc
}

func (s *state) vote(epoch uint64) {
	descriptors := []*descriptor{}
	for _, desc := range s.descriptors[epoch] {
		descriptors = append(descriptors, desc)
	}
	vote := s.getDocument(descriptors)
	signedVote := s.sign(vote)
	// save our own vote
	if _, ok := s.votes[epoch]; !ok {
		s.votes[epoch] = make(map[[eddsa.PublicKeySize]byte]*document)
	}
	if _, ok := s.votes[epoch][s.identityPubKey()]; !ok {
		s.votes[epoch][s.identityPubKey()] = signedVote
	} else {
		s.log.Errorf("failure: vote already present, this should never happen.")
		err := errors.New("failure: vote already present, this should never happen")
		s.s.fatalErrCh <- err
		return
	}
	s.sendVoteToAuthorities(signedVote.raw)
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
	cfg := &wire.SessionConfig{
		Authenticator:     s,
		AdditionalData:    []byte(""),
		AuthenticationKey: s.s.cfg.Debug.IdentityKey.ToECDH(),
		RandomReader:      rand.Reader,
	}
	session, err := wire.NewSession(cfg, true)
	if err != nil {
		return err
	}
	defer session.Close()
	cmd := &commands.Vote{
		Epoch:     s.votingEpoch,
		PublicKey: s.s.cfg.Debug.IdentityKey.PublicKey(),
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

func (s *state) agreedDescriptor(mixIdentity [eddsa.PublicKeySize]byte, votes []*pki.Document) *descriptor {
	if len(votes) < s.threshold {
		s.log.Debugf("generateConsensus excluding mix identity, less than threshold votes")
		return nil
	}

	seen := make(map[string][]*pki.Document)
	for _, vote := range votes {
		voteMixDesc, err := vote.GetMixByKey(mixIdentity[:])
		if err != nil {
			s.log.Errorf("votesAgree: GetMixByKey failure: %s", err)
			continue
		}
		rawVoteMixDesc, err := s11n.SerializeDescriptor(voteMixDesc)
		if err != nil {
			s.log.Errorf("s11n.SerializeDescriptor failure: %s", err)
			continue
		}

		rawVoteMixDescStr := string(rawVoteMixDesc)
		if _, ok := seen[rawVoteMixDescStr]; !ok {
			seen[rawVoteMixDescStr] = make([]*pki.Document, 0)
		}
		seen[rawVoteMixDescStr] = append(seen[rawVoteMixDescStr], vote)
	}
	for rawVoteMixDesc, votes := range seen {
		if len(votes) > s.threshold {
			voteMixDesc, err := s11n.VerifyAndParseDescriptor([]byte(rawVoteMixDesc), s.votingEpoch)
			if err != nil {
				return &descriptor{desc: voteMixDesc, raw: []byte(rawVoteMixDesc)}
			}
		}
	}
	return nil
}

func (s *state) sendConsensusToAuthorities(epoch uint64) {} // XXX

func (s *state) sendSignedDocumentToAuthorities(epoch uint64) {} // XXX

func (s *state) extractSignedDescriptor(id [eddsa.PublicKeySize]byte, rawDoc []byte) ([]byte, error) {
	_, rawDoc, err := s11n.VerifyAndParseDocument(rawDoc, s.s.identityKey.PublicKey())
	if err != nil {
		return nil, err
	}

	return nil, nil // XXX
}

func (s *state) tallyMixes(epoch uint64) []*descriptor {
	// Lock is held (called from the onWakeup hook).
	_, ok := s.votes[epoch]
	if !ok {
		s.log.Notice("No votes for epoch %v", epoch)
		return nil
	}
	if len(s.votes) <= s.threshold {
		s.log.Notice("Did not receive threshold number of votes.")
		return nil
	}

	mixTally := make(map[[eddsa.PublicKeySize]byte][]*pki.Document)
	for _, voteDoc := range s.votes[epoch] {
		for _, topoLayer := range voteDoc.doc.Topology {
			for _, voteDesc := range topoLayer {
				mixID := voteDesc.IdentityKey.ByteArray()
				mixTally[mixID] = append(mixTally[mixID], voteDoc.doc)
			}
		}
		for _, voteDesc := range voteDoc.doc.Providers {
			mixID := voteDesc.IdentityKey.ByteArray()
			mixTally[mixID] = append(mixTally[mixID], voteDoc.doc)
		}
	}

	var nodes []*descriptor
	for mixIdentity, votes := range mixTally {
		if desc := s.agreedDescriptor(mixIdentity, votes); desc != nil {
			nodes = append(nodes, desc)
		}
	}

	return nodes
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

func (s *state) tabulate(epoch uint64) {
	s.log.Noticef("Generating Consensus Document for epoch %v.", epoch)
	// include all the valid mixes from votes, including our own.
	mixes := s.tallyMixes(epoch)
	doc := s.getDocument(mixes)

	// Serialize and sign the Document.
	signed, err := s11n.MultiSignDocument(s.s.identityKey, s.signatures[epoch], doc)
	if err != nil {
		// This should basically always succeed.
		s.log.Errorf("Failed to sign document: %v", err)
		s.s.fatalErrCh <- err
		return
	}

	// Ensure the document is sane.
	pDoc, rawDoc, err := s11n.VerifyAndParseDocument([]byte(signed), s.s.identityKey.PublicKey())
	if err != nil {
		// This should basically always succeed.
		s.log.Errorf("Signed document failed validation: %v", err)
		s.s.fatalErrCh <- err
		return
	}
	// save the document
	d := &document{doc: pDoc, raw: rawDoc}
	if _, ok := s.documents[epoch]; !ok {
		s.documents[epoch] = d
	}
}

func (s *state) hasConsensus(epoch uint64) bool {
	doc, ok := s.documents[epoch]
	if !ok {
		return false
	}
	sigMap, err := s11n.VerifyPeerMulti(doc.raw, s.s.cfg.Authorities)
	if err == nil && len(sigMap) > s.threshold {
		return true
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

	rng := rand.NewMath()
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

	doc, rawDoc, err := s11n.VerifyAndParseDocument(vote.Payload, vote.PublicKey)
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
			raw: rawDoc,
			doc: doc,
		}
		s.log.Debug("Vote OK.")
		resp.ErrorCode = commands.VoteOk
	} else {
		// peer has voted previously, and has not yet submitted a signature
		if !s.dupSig(*vote) {
			signed, err := jose.ParseSigned(string(rawDoc))
			if err != nil {
				s.log.Errorf("onVoteUpload signature parse failure: %s", err)
				resp.ErrorCode = commands.VoteNotSigned
				return &resp
			}
			if len(signed.Signatures) == 1 {
				s.signatures[s.votingEpoch][vote.PublicKey.ByteArray()] = &signed.Signatures[0]
				resp.ErrorCode = commands.VoteOk
				return &resp
			} // else wrong number of signatures or no signature
			s.log.Error("Vote command invalid: wrong number of signature")
			resp.ErrorCode = commands.VoteNotSigned
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
	}

	st.Go(st.worker)
	return st, nil
}

func epochToBytes(e uint64) []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, e)
	return ret
}
