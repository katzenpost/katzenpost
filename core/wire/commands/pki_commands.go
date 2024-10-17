// SPDX-FileCopyrightText: Copyright (C) 2017  David Anthony Stainton, Yawning Angel
// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/binary"
	"errors"

	"github.com/katzenpost/hpqc/sign"
)

func voteOverhead(scheme sign.Scheme) int {
	return 8 + scheme.PublicKeySize()
}
func revealOverhead(scheme sign.Scheme) int {
	return 8 + scheme.PublicKeySize()
}
func certOverhead(scheme sign.Scheme) int {
	return 8 + scheme.PublicKeySize()
}
func sigOverhead(scheme sign.Scheme) int {
	return 8 + scheme.PublicKeySize()
}

// GetConsensus is a de-serialized get_consensus command.
type GetConsensus struct {
	Epoch              uint64
	Cmds               *Commands
	MixnetTransmission bool // if GetConsensus is sent over the mixnet, if true we need to pad the message
}

// ToBytes serializes the GetConsensus and returns the resulting byte slice.
func (c *GetConsensus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+getConsensusLength)
	out[0] = byte(getConsensus)
	binary.BigEndian.PutUint32(out[2:6], getConsensusLength)
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	if c.MixnetTransmission {
		// only pad if we are sending over the mixnet
		return c.Cmds.padToMaxCommandSize(out, true)
	}
	return out
}

func (c *GetConsensus) Length() int {
	return cmdOverhead + getConsensusLength
}

func getConsensusFromBytes(b []byte, cmds *Commands) (Command, error) {
	if len(b) != getConsensusLength {
		return nil, errInvalidCommand
	}

	r := new(GetConsensus)
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	r.Cmds = cmds
	return r, nil
}

// GetVote is a de-serialized get_vote command.
type GetVote struct {
	Cmds *Commands

	Epoch     uint64
	PublicKey sign.PublicKey
}

// ToBytes serializes the GetVote and returns the resulting slice.
func (v *GetVote) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8, cmdOverhead+voteOverhead(v.PublicKey.Scheme()))
	out[0] = byte(getVote)
	binary.BigEndian.PutUint32(out[2:6], uint32(voteOverhead(v.PublicKey.Scheme())))
	binary.BigEndian.PutUint64(out[6:14], v.Epoch)
	blob, err := v.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	out = append(out, blob...)
	return out
}

func (c *GetVote) Length() int {
	return cmdOverhead + 8 + c.Cmds.pkiSignatureScheme.PublicKeySize()
}

func getVoteFromBytes(b []byte, scheme sign.Scheme) (Command, error) {
	if len(b) != voteOverhead(scheme) {
		return nil, errInvalidCommand
	}
	r := new(GetVote)
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	var err error
	r.PublicKey, err = scheme.UnmarshalBinaryPublicKey(b[8 : scheme.PublicKeySize()+8])
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Consensus is a de-serialized consensus command.
type Consensus struct {
	ErrorCode uint8
	Payload   []byte
}

// ToBytes serializes the Consensus and returns the resulting byte slice.
func (c *Consensus) ToBytes() []byte {
	consensusLength := uint32(consensusBaseLength + len(c.Payload))
	out := make([]byte, cmdOverhead+consensusBaseLength, cmdOverhead+consensusLength)
	out[0] = byte(consensus) // out[1] is reserved
	binary.BigEndian.PutUint32(out[2:6], consensusLength)
	out[6] = c.ErrorCode
	out = append(out, c.Payload...)
	return out
}

func (c *Consensus) Length() int {
	return 0
}

func consensusFromBytes(b []byte) (Command, error) {
	if len(b) < consensusBaseLength {
		return nil, errInvalidCommand
	}

	r := new(Consensus)
	r.ErrorCode = b[0]
	if payloadLength := len(b) - consensusBaseLength; payloadLength > 0 {
		r.Payload = make([]byte, 0, payloadLength)
		r.Payload = append(r.Payload, b[consensusBaseLength:]...)
	}
	return r, nil
}

// PostDescriptor is a de-serialized post_descriptor command.
type PostDescriptor struct {
	Epoch   uint64
	Payload []byte
}

// ToBytes serializes the PostDescriptor and returns the resulting byte slice.
func (c *PostDescriptor) ToBytes() []byte {
	out := make([]byte, cmdOverhead+postDescriptorLength, cmdOverhead+postDescriptorLength+len(c.Payload))
	out[0] = byte(postDescriptor)
	binary.BigEndian.PutUint32(out[2:6], postDescriptorLength+uint32(len(c.Payload)))
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	out = append(out, c.Payload...)
	return out
}

func (c *PostDescriptor) Length() int {
	return 0
}

func postDescriptorFromBytes(b []byte) (Command, error) {
	if len(b) < postDescriptorLength {
		return nil, errInvalidCommand
	}

	r := new(PostDescriptor)
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	r.Payload = make([]byte, 0, len(b)-postDescriptorLength)
	r.Payload = append(r.Payload, b[postDescriptorLength:]...)
	return r, nil
}

// PostDescriptorStatus is a de-serialized post_descriptor_status command.
type PostDescriptorStatus struct {
	ErrorCode uint8
}

func postDescriptorStatusFromBytes(b []byte) (Command, error) {
	if len(b) != postDescriptorStatusLength {
		return nil, errInvalidCommand
	}

	r := new(PostDescriptorStatus)
	r.ErrorCode = b[0]
	return r, nil
}

// ToBytes serializes the PostDescriptorStatus and returns the resulting byte
// slice.
func (c *PostDescriptorStatus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+postDescriptorStatusLength)
	out[0] = byte(postDescriptorStatus)
	binary.BigEndian.PutUint32(out[2:6], postDescriptorStatusLength)
	out[6] = c.ErrorCode
	return out
}

func (c *PostDescriptorStatus) Length() int {
	return 0
}

// Reveal is a de-serialized reveal command exchanged by authorities.
type Reveal struct {
	Epoch     uint64
	PublicKey sign.PublicKey
	Payload   []byte
}

// ToBytes serializes the Reveal and returns the resulting byte slice.
func (r *Reveal) ToBytes() []byte {
	out := make([]byte, cmdOverhead+revealOverhead(r.PublicKey.Scheme()))
	out[0] = byte(reveal)
	// out[1] reserved
	binary.BigEndian.PutUint32(out[2:6], uint32(revealOverhead(r.PublicKey.Scheme())+len(r.Payload)))
	binary.BigEndian.PutUint64(out[6:14], r.Epoch)
	blob, err := r.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	copy(out[14:14+r.PublicKey.Scheme().PublicKeySize()], blob)
	out = append(out, r.Payload...)
	return out
}

func (c *Reveal) Length() int {
	return 0
}

func revealFromBytes(b []byte, scheme sign.Scheme) (Command, error) {
	if len(b) < revealOverhead(scheme) {
		return nil, errors.New(" wtf: errInvalidCommand")
	}

	r := new(Reveal)
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	var err error
	r.PublicKey, err = scheme.UnmarshalBinaryPublicKey(b[8 : 8+scheme.PublicKeySize()])
	if err != nil {
		return nil, err
	}
	r.Payload = make([]byte, 0, len(b)-revealOverhead(scheme))
	r.Payload = append(r.Payload, b[revealOverhead(scheme):]...)
	return r, nil
}

// RevealStatus is a de-serialized revealStatus command.
type RevealStatus struct {
	ErrorCode uint8
}

func revealStatusFromBytes(b []byte) (Command, error) {
	if len(b) != revealStatusLength {
		return nil, errors.New(" wtf: errInvalidCommand")
	}

	r := new(RevealStatus)
	r.ErrorCode = b[0]
	return r, nil
}

// ToBytes serializes the RevealStatus and returns the resulting byte slice.
func (r *RevealStatus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+revealStatusLength)
	out[0] = byte(revealStatus)
	binary.BigEndian.PutUint32(out[2:6], revealStatusLength)
	out[6] = r.ErrorCode
	return out
}

func (c *RevealStatus) Length() int {
	return 0
}

// Vote is a vote which is exchanged by Directory Authorities.
type Vote struct {
	Epoch     uint64
	PublicKey sign.PublicKey
	Payload   []byte
}

func voteFromBytes(b []byte, scheme sign.Scheme) (Command, error) {
	r := new(Vote)
	if len(b) < voteOverhead(scheme) {
		return nil, errInvalidCommand
	}
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	var err error
	r.PublicKey, err = scheme.UnmarshalBinaryPublicKey(b[8 : 8+scheme.PublicKeySize()])
	if err != nil {
		return nil, err
	}
	r.Payload = make([]byte, 0, len(b)-voteOverhead(scheme))
	r.Payload = append(r.Payload, b[voteOverhead(scheme):]...)
	return r, nil
}

// ToBytes serializes the Vote and returns the resulting slice.
func (c *Vote) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8, cmdOverhead+voteOverhead(c.PublicKey.Scheme())+len(c.Payload))
	out[0] = byte(vote)
	binary.BigEndian.PutUint32(out[2:6], uint32(voteOverhead(c.PublicKey.Scheme())+len(c.Payload)))
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	blob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	out = append(out, blob...)
	out = append(out, c.Payload...)
	return out
}

func (c *Vote) Length() int {
	return 0
}

// VoteStatus is a resonse status for a Vote command.
type VoteStatus struct {
	ErrorCode uint8
}

// ToBytes serializes the VoteStatus and returns the resulting slice.
func (c *VoteStatus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+voteStatusLength)
	out[0] = byte(voteStatus)
	binary.BigEndian.PutUint32(out[2:6], voteStatusLength)
	out[6] = c.ErrorCode
	return out
}

func (c *VoteStatus) Length() int {
	return 0
}

func voteStatusFromBytes(b []byte) (Command, error) {
	if len(b) != voteStatusLength {
		return nil, errInvalidCommand
	}

	r := new(VoteStatus)
	r.ErrorCode = b[0]
	return r, nil
}

// Cert is a potential consensus which is exchanged by Directory Authorities.
type Cert struct {
	Epoch     uint64
	PublicKey sign.PublicKey
	Payload   []byte
}

func certFromBytes(b []byte, scheme sign.Scheme) (Command, error) {
	r := new(Cert)
	if len(b) < certOverhead(scheme) {
		return nil, errInvalidCommand
	}
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	var err error
	r.PublicKey, err = scheme.UnmarshalBinaryPublicKey(b[8 : 8+scheme.PublicKeySize()])
	if err != nil {
		return nil, err
	}
	r.Payload = make([]byte, 0, len(b)-certOverhead(scheme))
	r.Payload = append(r.Payload, b[certOverhead(scheme):]...)
	return r, nil
}

// ToBytes serializes the Cert and returns the resulting slice.
func (c *Cert) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8, cmdOverhead+certOverhead(c.PublicKey.Scheme())+len(c.Payload))
	out[0] = byte(certificate)
	binary.BigEndian.PutUint32(out[2:6], uint32(certOverhead(c.PublicKey.Scheme())+len(c.Payload)))
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	blob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	out = append(out, blob...)
	out = append(out, c.Payload...)
	return out
}

func (c *Cert) Length() int {
	return 0
}

// CertStatus is a resonse status for a Cert command.
type CertStatus struct {
	ErrorCode uint8
}

// ToBytes serializes the CertStatus and returns the resulting slice.
func (c *CertStatus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+certStatusLength)
	out[0] = byte(certStatus)
	binary.BigEndian.PutUint32(out[2:6], certStatusLength)
	out[6] = c.ErrorCode
	return out
}

func (c *CertStatus) Length() int {
	return 0
}

func certStatusFromBytes(b []byte) (Command, error) {
	if len(b) != certStatusLength {
		return nil, errInvalidCommand
	}

	r := new(CertStatus)
	r.ErrorCode = b[0]
	return r, nil
}

// Sig is a signature which is exchanged by Directory Authorities.
type Sig struct {
	Epoch     uint64
	PublicKey sign.PublicKey
	Payload   []byte
}

func sigFromBytes(b []byte, scheme sign.Scheme) (Command, error) {
	r := new(Sig)
	if len(b) < sigOverhead(scheme) {
		return nil, errInvalidCommand
	}
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	var err error
	r.PublicKey, err = scheme.UnmarshalBinaryPublicKey(b[8 : 8+scheme.PublicKeySize()])
	if err != nil {
		return nil, err
	}
	r.Payload = make([]byte, 0, len(b)-sigOverhead(scheme))
	r.Payload = append(r.Payload, b[sigOverhead(scheme):]...)
	return r, nil
}

// ToBytes serializes the Sig and returns the resulting slice.
func (c *Sig) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8, cmdOverhead+sigOverhead(c.PublicKey.Scheme())+len(c.Payload))
	out[0] = byte(sig)
	binary.BigEndian.PutUint32(out[2:6], uint32(sigOverhead(c.PublicKey.Scheme())+len(c.Payload)))
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	blob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	out = append(out, blob...)
	out = append(out, c.Payload...)
	return out
}

func (c *Sig) Length() int {
	return 0
}

// SigStatus is a resonse status for a Sig command.
type SigStatus struct {
	ErrorCode uint8
}

// ToBytes serializes the Status and returns the resulting slice.
func (c *SigStatus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+sigStatusLength)
	out[0] = byte(sigStatus)
	binary.BigEndian.PutUint32(out[2:6], sigStatusLength)
	out[6] = c.ErrorCode
	return out
}

func (c *SigStatus) Length() int {
	return 0
}

func sigStatusFromBytes(b []byte) (Command, error) {
	if len(b) != sigStatusLength {
		return nil, errInvalidCommand
	}

	r := new(SigStatus)
	r.ErrorCode = b[0]
	return r, nil
}
