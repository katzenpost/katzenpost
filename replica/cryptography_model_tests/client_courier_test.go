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

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mrhybrid"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
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
	KEMScheme        kem.Scheme
	PrivateKey       kem.PrivateKey
	PublicKey        kem.PublicKey
	DB               map[[32]byte]*Box
	ID               uint8
}

func NewReplicas(count int, scheme kem.Scheme, cmds *commands.Commands, sphinxGeo *geo.Geometry, sphinxNIKEScheme nike.Scheme) []*Replica {
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
			KEMScheme:        scheme,
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

	scheme := mrhybrid.NewScheme(r.KEMScheme)

	ct := &mrhybrid.Ciphertext{
		KEMCiphertexts: [][]byte{replicaMessage.KEMCiphertext},
		DEKCiphertexts: [][]byte{replicaMessage.DEK[:]},
		Envelope:       replicaMessage.Ciphertext,
	}

	derivedKey, requestRaw, err := scheme.Decapsulate(r.PrivateKey, ct)
	if err != nil {
		panic(err)
	}

	msg, err := pigeonhole.ParseReplicaInnerMessage(requestRaw)
	if err != nil {
		panic(err)
	}

	envelopeHash := replicaMessage.EnvelopeHash()
	switch {
	case msg.ReadMsg != nil:
		readReply := r.handleReplicaRead(msg.ReadMsg)
		replyInnerMessage := pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 0, // 0 = read_reply
			ReadReply:   readReply,
		}
		replyInnerMessageBlob := replyInnerMessage.Bytes()
		envelopeReply, err := scheme.EnvelopeReply(derivedKey, replyInnerMessageBlob)
		if err != nil {
			panic(err)
		}
		reply := &commands.ReplicaMessageReply{
			Cmds:          r.Cmds,
			ErrorCode:     0, // Zero means success.
			EnvelopeHash:  envelopeHash,
			EnvelopeReply: envelopeReply,
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
		envelopeReply, err := scheme.EnvelopeReply(derivedKey, replyInnerMessageBlob)
		if err != nil {
			panic(err)
		}
		reply := &commands.ReplicaMessageReply{
			Cmds:          r.Cmds,
			ErrorCode:     0, // Zero means success.
			EnvelopeHash:  envelopeHash,
			EnvelopeReply: envelopeReply,
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
	PigeonholeGeo *pgeo.Geometry
	ReplicaScheme kem.Scheme
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
		Cmds:               c.Cmds,
		PigeonholeGeometry: c.PigeonholeGeo,
		Scheme:             c.ReplicaScheme,

		KEMCiphertext: courierMessage.KemCiphertext1,
		DEK:           &courierMessage.Dek1,
		Ciphertext:    courierMessage.Ciphertext,
	})

	// replica 1
	secondReplicaID := courierMessage.IntermediateReplicas[1]
	c.SendToReplica(secondReplicaID, &commands.ReplicaMessage{
		Cmds:               c.Cmds,
		PigeonholeGeometry: c.PigeonholeGeo,
		Scheme:             c.ReplicaScheme,

		KEMCiphertext: courierMessage.KemCiphertext2,
		DEK:           &courierMessage.Dek2,
		Ciphertext:    courierMessage.Ciphertext,
	})
	reply := &pigeonhole.CourierEnvelopeReply{
		EnvelopeHash: [32]uint8{},
		ReplyIndex:   0,
		PayloadLen:   uint32(len(reply0.EnvelopeReply)),
		Payload:      reply0.EnvelopeReply,
		ErrorCode:    0,
	}
	return reply
}

type ClientWriter struct {
	WriteCap       *bacap.WriteCap
	StatefulWriter *bacap.StatefulWriter
	MRHybridScheme *mrhybrid.Scheme
	Replicas       []*Replica
}

func NewClientWriter(replicas []*Replica, MRHybridScheme *mrhybrid.Scheme, ctx []byte) *ClientWriter {
	owner, err := bacap.NewWriteCap(rand.Reader)
	if err != nil {
		panic(err)
	}
	statefulWriter, err := bacap.NewStatefulWriter(owner, ctx)
	if err != nil {
		panic(err)
	}
	return &ClientWriter{
		WriteCap:       owner,
		StatefulWriter: statefulWriter,
		MRHybridScheme: MRHybridScheme,
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

	replicaPubKeys := make([]kem.PublicKey, 2)
	for i := 0; i < 2; i++ {
		replicaPubKeys[i] = c.Replicas[i].PublicKey
	}

	_, mkemCiphertext, err := c.MRHybridScheme.Encapsulate(
		replicaPubKeys, msg.Bytes())
	if err != nil {
		panic(err)
	}

	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1}, // indices to pkidoc's StorageReplicas
		Dek1:                 [mrhybrid.DEKSize]byte(mkemCiphertext.DEKCiphertexts[0]),
		Dek2:                 [mrhybrid.DEKSize]byte(mkemCiphertext.DEKCiphertexts[1]),
		ReplyIndex:           0,
		KemCiphertext1Len:    uint32(len(mkemCiphertext.KEMCiphertexts[0])),
		KemCiphertext1:       mkemCiphertext.KEMCiphertexts[0],
		KemCiphertext2Len:    uint32(len(mkemCiphertext.KEMCiphertexts[1])),
		KemCiphertext2:       mkemCiphertext.KEMCiphertexts[1],
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}
	return envelope
}

type ClientReader struct {
	ReadCap        *bacap.ReadCap
	StatefulReader *bacap.StatefulReader
	MRHybridScheme *mrhybrid.Scheme
	Replicas       []*Replica
}

func NewClientReader(replicas []*Replica, MRHybridScheme *mrhybrid.Scheme, readCap *bacap.ReadCap, ctx []byte) *ClientReader {
	statefulReader, err := bacap.NewStatefulReader(readCap, ctx)
	if err != nil {
		panic(err)
	}
	return &ClientReader{
		ReadCap:        readCap,
		StatefulReader: statefulReader,
		MRHybridScheme: MRHybridScheme,
		Replicas:       replicas,
	}
}

// ComposeReadNextMessage returns the derived keys for both intermediate
// replicas (index-aligned with the envelope's IntermediateReplicas), since
// mrhybrid has no shared ephemeral keypair to decapsulate a reply with —
// the caller doesn't know in advance which of the two replicas will answer,
// so it tries both derived keys, mirroring EnvelopeDescriptor.DerivedKeys
// in the real client (client/envelope_descriptor.go).
func (c *ClientReader) ComposeReadNextMessage() ([2][]byte, *pigeonhole.CourierEnvelope) {
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

	replicaPubKeys := make([]kem.PublicKey, 2)
	for i := 0; i < 2; i++ {
		replicaPubKeys[i] = c.Replicas[i].PublicKey
	}

	derivedKeys, mkemCiphertext, err := c.MRHybridScheme.Encapsulate(replicaPubKeys, msg.Bytes())
	if err != nil {
		panic(err)
	}
	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1}, // indices to pkidoc's StorageReplicas
		Dek1:                 [mrhybrid.DEKSize]byte(mkemCiphertext.DEKCiphertexts[0]),
		Dek2:                 [mrhybrid.DEKSize]byte(mkemCiphertext.DEKCiphertexts[1]),
		ReplyIndex:           0,
		KemCiphertext1Len:    uint32(len(mkemCiphertext.KEMCiphertexts[0])),
		KemCiphertext1:       mkemCiphertext.KEMCiphertexts[0],
		KemCiphertext2Len:    uint32(len(mkemCiphertext.KEMCiphertexts[1])),
		KemCiphertext2:       mkemCiphertext.KEMCiphertexts[1],
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}
	return [2][]byte{derivedKeys[0], derivedKeys[1]}, envelope
}

func TestClientCourierProtocolFlow(t *testing.T) {
	sphinxGeo := geo.GeometryFromUserForwardPayloadLength(nikeschemes.ByName("X25519"), 5000, true, 5)
	sphinxNikeScheme := nikeschemes.ByName("X25519")
	scheme := kemschemes.ByName("x25519")
	cmds := commands.NewStorageReplicaCommands(sphinxGeo, scheme)

	mrhybridScheme := mrhybrid.NewScheme(scheme)

	replicas := NewReplicas(4, scheme, cmds, sphinxGeo, sphinxNikeScheme)
	require.NotNil(t, replicas)
	for i := 0; i < len(replicas); i++ {
		if replicas[i] == nil {
			panic("replica is nil")
		}
	}

	// Create pigeonhole geometry from sphinx geometry
	pigeonholeGeo, err := pgeo.NewGeometryFromSphinx(sphinxGeo, scheme)
	require.NoError(t, err)

	courier := &Courier{
		Replicas:      replicas,
		Cmds:          cmds,
		Geo:           sphinxGeo,
		PigeonholeGeo: pigeonholeGeo,
		ReplicaScheme: scheme,
	}

	ctx := []byte("katzenpost pigeonhole context")

	// --- Alice creates a BACAP sequence and gives Bob a sequence read capability

	alice := NewClientWriter(replicas, mrhybridScheme, ctx)
	readCap := alice.WriteCap.ReadCap()
	bob := NewClientReader(replicas, mrhybridScheme, readCap, ctx)

	// --- Alice encrypts a message to Bob in the BACAP sequence.
	// and it gets sent to the storage replicas.

	aliceMsg1 := []byte("Bob, Beware they are jamming GPS.")
	messageToSend := alice.ComposeSendNextMessage(aliceMsg1)
	courierReply1 := courier.ReceiveClientQuery(messageToSend.Bytes())
	require.NotNil(t, courierReply1)

	// --- Bob retrieves and decrypts the message

	bobDerivedKeys, bobReceiveRequest := bob.ComposeReadNextMessage()
	bobReply1 := courier.ReceiveClientQuery(bobReceiveRequest.Bytes())

	// ReceiveClientQuery always answers from IntermediateReplicas[0] (see
	// its reply0/firstReplicaID handling above), so the matching derived
	// key is bobDerivedKeys[0].
	rawInnerMsg, err := mrhybridScheme.DecryptEnvelope(bobDerivedKeys[0], bobReply1.Payload)
	require.NoError(t, err)

	// pigeonhole.ReplicaMessageReplyInnerMessage
	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
	require.NoError(t, err)
	require.NotNil(t, innerMsg.ReadReply)

	plaintext, err := bob.StatefulReader.DecryptNext(ctx, innerMsg.ReadReply.BoxID, innerMsg.ReadReply.Payload, innerMsg.ReadReply.Signature)
	require.NoError(t, err)

	require.Equal(t, aliceMsg1[:], plaintext[:])
}
