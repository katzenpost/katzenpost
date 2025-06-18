// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package tests contains unit tests which demonstrate the Pigeonhole
// protocol flow faithfully using all the proper message types and
// performing all the cryptographic calcultaions with acuracy while
// modeling the networking with very little detail. All models are wrong.
// Some models are useful.
package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

type Box struct {
	// BoxID uniquely identifies a box.
	BoxID *[32]byte

	// Signature covers the given Payload field and
	// is verifiable with the BoxID which is also the public key.
	Signature *[64]byte

	// Payload is encrypted and MAC'ed.
	Payload []byte
}

type Replica struct {
	Cmds             *commands.Commands
	SphinxGeo        *geo.Geometry
	SphinxNIKEScheme nike.Scheme
	NIKEScheme       nike.Scheme
	PrivateKey       nike.PrivateKey
	PublicKey        nike.PublicKey
	DB               map[[32]byte]*Box
	ID               uint8
}

func NewReplicas(count int, scheme nike.Scheme, cmds *commands.Commands, sphinxGeo *geo.Geometry, sphinxNIKEScheme nike.Scheme) []*Replica {
	replicas := make([]*Replica, count)
	for i := 0; i < count; i++ {
		pk, sk, err := scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		replicas[i] = &Replica{
			Cmds:             cmds,
			SphinxGeo:        sphinxGeo,
			SphinxNIKEScheme: sphinxNIKEScheme,
			NIKEScheme:       scheme,
			PrivateKey:       sk,
			PublicKey:        pk,
			DB:               make(map[[32]byte]*Box),
			ID:               uint8(i),
		}
	}
	return replicas
}

func (r *Replica) handleReplicaRead(replicaRead *pigeonhole.ReplicaRead) *pigeonhole.ReplicaReadReply {
	const (
		successCode = 0
		failCode    = 1
	)
	box, ok := r.DB[replicaRead.BoxID]
	if !ok {
		return &pigeonhole.ReplicaReadReply{
			ErrorCode:  failCode,
			BoxID:      [32]uint8{},
			Signature:  [64]uint8{},
			PayloadLen: 0,
			Payload:    nil,
		}
	}
	return &pigeonhole.ReplicaReadReply{
		ErrorCode:  successCode,
		BoxID:      *box.BoxID,
		Signature:  *box.Signature,
		PayloadLen: uint32(len(box.Payload)),
		Payload:    box.Payload,
	}
}

func (r *Replica) handleReplicaWrite(replicaWrite *pigeonhole.ReplicaWrite) *pigeonhole.ReplicaWriteReply {
	const (
		successCode = 0
		failCode    = 1
	)
	s := ed25519.Scheme()
	verifyKey, err := s.UnmarshalBinaryPublicKey(replicaWrite.BoxID[:])
	if err != nil {
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: failCode,
		}
	}
	if !s.Verify(verifyKey, replicaWrite.Payload, replicaWrite.Signature[:], nil) {
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: failCode,
		}
	}

	r.DB[replicaWrite.BoxID] = &Box{
		BoxID:     &replicaWrite.BoxID,
		Signature: &replicaWrite.Signature,
		Payload:   replicaWrite.Payload,
	}

	return &pigeonhole.ReplicaWriteReply{
		ErrorCode: successCode,
	}
}

func (r *Replica) ReceiveMessage(replicaMessageRaw []byte) []byte {
	cmd, err := r.Cmds.FromBytes(replicaMessageRaw)
	if err != nil {
		panic(err)
	}

	var replicaMessage *commands.ReplicaMessage
	switch v := cmd.(type) {
	case *commands.ReplicaMessage:
		replicaMessage = v
	default:
		panic("Replica received invalid message")
	}

	scheme := mkem.NewScheme(r.NIKEScheme)

	ephemeralPublicKey, err := r.NIKEScheme.UnmarshalBinaryPublicKey(replicaMessage.SenderEPubKey)
	if err != nil {
		panic(err)
	}
	ct := &mkem.Ciphertext{
		EphemeralPublicKey: ephemeralPublicKey,
		DEKCiphertexts:     []*[mkem.DEKSize]byte{replicaMessage.DEK},
		Envelope:           replicaMessage.Ciphertext,
	}

	requestRaw, err := scheme.Decapsulate(r.PrivateKey, ct)
	if err != nil {
		panic(err)
	}

	msg, err := pigeonhole.ParseReplicaInnerMessage(requestRaw)
	if err != nil {
		panic(err)
	}

	envelopeHash := blake2b.Sum256(replicaMessage.SenderEPubKey[:])
	senderpubkey, err := r.NIKEScheme.UnmarshalBinaryPublicKey(replicaMessage.SenderEPubKey[:])
	if err != nil {
		panic(err)
	}
	switch {
	case msg.ReadMsg != nil:
		readReply := r.handleReplicaRead(msg.ReadMsg)
		replyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 0, // 0 = read_reply
			ReadReply:   readReply,
		}
		replyInnerMessageBlob := replyInnerMessage.Bytes()
		envelopeReply := scheme.EnvelopeReply(r.PrivateKey, senderpubkey, replyInnerMessageBlob)
		reply := &commands.ReplicaMessageReply{
			Cmds:          r.Cmds,
			ErrorCode:     0, // Zero means success.
			EnvelopeHash:  &envelopeHash,
			EnvelopeReply: envelopeReply.Envelope,
			ReplicaID:     r.ID,
		}
		return reply.ToBytes()
	case msg.WriteMsg != nil:
		writeReply := r.handleReplicaWrite(msg.WriteMsg)
		// XXX c.l.server.connector.DispatchReplication(myCmd)
		replyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 1, // 1 = write_reply
			WriteReply:  writeReply,
		}
		replyInnerMessageBlob := replyInnerMessage.Bytes()
		envelopeReply := scheme.EnvelopeReply(r.PrivateKey, senderpubkey, replyInnerMessageBlob)
		reply := &commands.ReplicaMessageReply{
			Cmds:          r.Cmds,
			ErrorCode:     0, // Zero means success.
			EnvelopeHash:  &envelopeHash,
			EnvelopeReply: envelopeReply.Envelope,
			ReplicaID:     r.ID,
		}
		return reply.ToBytes()
	default:
		panic("wtf")
	}
}

type Courier struct {
	Replicas      []*Replica
	Cmds          *commands.Commands
	Geo           *geo.Geometry
	ReplicaScheme nike.Scheme
}

func (c *Courier) SendToReplica(id uint8, replicaMessage *commands.ReplicaMessage) *commands.ReplicaMessageReply {
	replyBlob := c.Replicas[id].ReceiveMessage(replicaMessage.ToBytes())
	cmd, err := c.Cmds.FromBytes(replyBlob)
	if err != nil {
		panic(err)
	}

	switch v := cmd.(type) {
	case *commands.ReplicaMessageReply:
		return v
	default:
		panic("Courier received invalid message")
	}
}

func (c *Courier) ReceiveClientQuery(query []byte) *pigeonhole.CourierEnvelopeReply {
	courierMessage, err := pigeonhole.ParseCourierEnvelope(query)
	if err != nil {
		panic(err)
	}

	// replica 0
	firstReplicaID := courierMessage.IntermediateReplicas[0]
	reply0 := c.SendToReplica(firstReplicaID, &commands.ReplicaMessage{
		Cmds:   c.Cmds,
		Geo:    c.Geo,
		Scheme: c.ReplicaScheme,

		SenderEPubKey: courierMessage.SenderPubkey,
		DEK:           &courierMessage.Dek1,
		Ciphertext:    courierMessage.Ciphertext,
	})

	// replica 1
	secondReplicaID := courierMessage.IntermediateReplicas[1]
	c.SendToReplica(secondReplicaID, &commands.ReplicaMessage{
		Cmds:   c.Cmds,
		Geo:    c.Geo,
		Scheme: c.ReplicaScheme,

		SenderEPubKey: courierMessage.SenderPubkey,
		DEK:           &courierMessage.Dek2,
		Ciphertext:    courierMessage.Ciphertext,
	})
	reply := &pigeonhole.CourierEnvelopeReply{
		EnvelopeHash: [32]uint8{}, // TODO: Set proper envelope hash
		ReplyIndex:   0,
		PayloadLen:   uint32(len(reply0.EnvelopeReply)),
		Payload:      reply0.EnvelopeReply,
		ErrorCode:    0,
	}
	return reply
}

type ClientWriter struct {
	BoxOwnerCap    *bacap.BoxOwnerCap
	StatefulWriter *bacap.StatefulWriter
	MKEMNikeScheme *mkem.Scheme
	Replicas       []*Replica
}

func NewClientWriter(replicas []*Replica, MKEMNikeScheme *mkem.Scheme, ctx []byte) *ClientWriter {
	owner, err := bacap.NewBoxOwnerCap(rand.Reader)
	if err != nil {
		panic(err)
	}
	statefulWriter, err := bacap.NewStatefulWriter(owner, ctx)
	if err != nil {
		panic(err)
	}
	return &ClientWriter{
		BoxOwnerCap:    owner,
		StatefulWriter: statefulWriter,
		MKEMNikeScheme: MKEMNikeScheme,
		Replicas:       replicas,
	}
}

func (c *ClientWriter) ComposeSendNextMessage(message []byte) *pigeonhole.CourierEnvelope {
	boxID, ciphertext, sigraw, err := c.StatefulWriter.EncryptNext(message)
	if err != nil {
		panic(err)
	}

	sig := &[bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	writeRequest := &pigeonhole.ReplicaWrite{
		BoxID:      boxID,
		Signature:  *sig,
		PayloadLen: uint32(len(ciphertext)),
		Payload:    ciphertext,
	}
	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg:    writeRequest,
	}

	replicaPubKeys := make([]nike.PublicKey, 2)
	for i := 0; i < 2; i++ {
		replicaPubKeys[i] = c.Replicas[i].PublicKey
	}

	mkemPrivateKey, mkemCiphertext := c.MKEMNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()

	senderPubkey := mkemPublicKey.Bytes()
	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1}, // indices to pkidoc's StorageReplicas
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		SenderPubkeyLen:      uint16(len(senderPubkey)),
		SenderPubkey:         senderPubkey,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               0, // 0 = write
	}
	return envelope
}

type ClientReader struct {
	UniversalReadCap *bacap.UniversalReadCap
	StatefulReader   *bacap.StatefulReader
	MKEMNikeScheme   *mkem.Scheme
	Replicas         []*Replica
}

func NewClientReader(replicas []*Replica, MKEMNikeScheme *mkem.Scheme, universalReadCap *bacap.UniversalReadCap, ctx []byte) *ClientReader {
	statefulReader, err := bacap.NewStatefulReader(universalReadCap, ctx)
	if err != nil {
		panic(err)
	}
	return &ClientReader{
		UniversalReadCap: universalReadCap,
		StatefulReader:   statefulReader,
		MKEMNikeScheme:   MKEMNikeScheme,
		Replicas:         replicas,
	}
}

func (c *ClientReader) ComposeReadNextMessage() (nike.PrivateKey, *pigeonhole.CourierEnvelope) {
	boxid, err := c.StatefulReader.NextBoxID()
	if err != nil {
		panic(err)
	}
	readMsg := &pigeonhole.ReplicaRead{
		BoxID: *boxid,
	}
	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg:     readMsg,
	}

	replicaPubKeys := make([]nike.PublicKey, 2)
	for i := 0; i < 2; i++ {
		replicaPubKeys[i] = c.Replicas[i].PublicKey
	}

	mkemPrivateKey, mkemCiphertext := c.MKEMNikeScheme.Encapsulate(replicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()
	senderPubkey := mkemPublicKey.Bytes()
	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1}, // indices to pkidoc's StorageReplicas
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		SenderPubkeyLen:      uint16(len(senderPubkey)),
		SenderPubkey:         senderPubkey,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               1, // 1 = read
	}
	return mkemPrivateKey, envelope
}

func TestClientCourierProtocolFlow(t *testing.T) {
	sphinxGeo := geo.GeometryFromUserForwardPayloadLength(schemes.ByName("X25519"), 5000, true, 5)
	sphinxNikeScheme := schemes.ByName("X25519")
	scheme := schemes.ByName("CTIDH1024-X25519")
	cmds := commands.NewStorageReplicaCommands(sphinxGeo, scheme)

	mkemNikeScheme := mkem.NewScheme(scheme)

	replicas := NewReplicas(4, scheme, cmds, sphinxGeo, sphinxNikeScheme)
	require.NotNil(t, replicas)
	for i := 0; i < len(replicas); i++ {
		if replicas[i] == nil {
			panic("replica is nil")
		}
	}

	courier := &Courier{
		Replicas:      replicas,
		Cmds:          cmds,
		Geo:           sphinxGeo,
		ReplicaScheme: scheme,
	}

	ctx := []byte("katzenpost pigeonhole context")

	// --- Alice creates a BACAP sequence and gives Bob a sequence read capability

	alice := NewClientWriter(replicas, mkemNikeScheme, ctx)
	ureadcap := alice.BoxOwnerCap.UniversalReadCap()
	bob := NewClientReader(replicas, mkemNikeScheme, ureadcap, ctx)

	// --- Alice encrypts a message to Bob in the BACAP sequence.
	// and it gets sent to the storage replicas.

	aliceMsg1 := []byte("Bob, Beware they are jamming GPS.")
	messageToSend := alice.ComposeSendNextMessage(aliceMsg1)
	courierReply1 := courier.ReceiveClientQuery(messageToSend.Bytes())
	require.NotNil(t, courierReply1)

	// --- Bob retrieves and decrypts the message

	bobPrivateKey1, bobReceiveRequest := bob.ComposeReadNextMessage()
	bobReply1 := courier.ReceiveClientQuery(bobReceiveRequest.Bytes())

	rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(bobPrivateKey1, replicas[0].PublicKey, bobReply1.Payload)
	require.NoError(t, err)

	// pigeonhole.ReplicaMessageReplyInnerMessage
	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
	require.NoError(t, err)
	require.NotNil(t, innerMsg.ReadReply)

	plaintext, err := bob.StatefulReader.DecryptNext(ctx, innerMsg.ReadReply.BoxID, innerMsg.ReadReply.Payload, innerMsg.ReadReply.Signature)
	require.NoError(t, err)

	require.Equal(t, aliceMsg1[:], plaintext[:])
}
