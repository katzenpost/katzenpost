// SPDX-FileCopyrightText: (c) 2026  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// newKeypair creates a new keypair for use with the Pigeonhole protocol.
func (d *Daemon) newKeypair(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	seed := request.NewKeypair.Seed
	if len(seed) < 32 {
		d.sendNewKeypairError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	rng, err := rand.NewDeterministicRandReader(seed)
	if err != nil {
		d.sendNewKeypairError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	writeCap, err := bacap.NewWriteCap(rng)
	if err != nil {
		d.sendNewKeypairError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	readCap := writeCap.ReadCap()
	conn.sendResponse(&Response{
		AppID: request.AppID,
		NewKeypairReply: &thin.NewKeypairReply{
			WriteCap:  writeCap,
			ReadCap:   readCap,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendNewKeypairError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		NewKeypairReply: &thin.NewKeypairReply{
			QueryID:   request.NewKeypair.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// encryptRead encrypts a read operation for the Pigeonhole protocol.
// This does not perform any mixnet communication, it just prepares the
// encrypted envelope that the thin client will send later.
func (d *Daemon) encryptRead(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	readCap := request.EncryptRead.ReadCap
	if readCap == nil {
		d.log.Error("encryptRead: ReadCap is nil")
		d.sendEncryptReadError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	messageBoxIndex := request.EncryptRead.MessageBoxIndex
	if messageBoxIndex == nil {
		d.log.Error("encryptRead: MessageBoxIndex is nil")
		d.sendEncryptReadError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Create a StatefulReader from the provided ReadCap and MessageBoxIndex
	statefulReader, err := bacap.NewStatefulReaderWithIndex(readCap, constants.PIGEONHOLE_CTX, messageBoxIndex)
	if err != nil {
		d.log.Errorf("encryptRead: failed to create stateful reader: %v", err)
		d.sendEncryptReadError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Get the BoxID for this read operation
	boxID, err := statefulReader.NextBoxID()
	if err != nil {
		d.log.Errorf("encryptRead: failed to get next box ID: %v", err)
		d.sendEncryptReadError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Get the next message index (for the thin client to use on subsequent operations)
	nextMessageIndex, err := statefulReader.GetNextMessageIndex()
	if err != nil {
		d.log.Errorf("encryptRead: failed to get next message index: %v", err)
		d.sendEncryptReadError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Create the ReplicaInnerMessage for a read operation
	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg: &pigeonhole.ReplicaRead{
			BoxID: *boxID,
		},
	}

	// Get the current PKI document
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Error("encryptRead: no PKI document available")
		d.sendEncryptReadError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Create the envelope using the existing createEnvelopeFromMessage function
	courierEnvelope, envelopePrivateKey, err := createEnvelopeFromMessage(msg, doc, true, 0)
	if err != nil {
		d.log.Errorf("encryptRead: failed to create envelope: %v", err)
		d.sendEncryptReadError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Create the EnvelopeDescriptor
	envHash := courierEnvelope.EnvelopeHash()
	envelopeDesc := &EnvelopeDescriptor{
		Epoch:       doc.Epoch,
		ReplicaNums: courierEnvelope.IntermediateReplicas,
		EnvelopeKey: envelopePrivateKey.Bytes(),
	}

	envelopeDescriptorBytes, err := envelopeDesc.Bytes()
	if err != nil {
		d.log.Errorf("encryptRead: failed to serialize envelope descriptor: %v", err)
		d.sendEncryptReadError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Create the CourierQuery and serialize it as MessageCiphertext
	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}

	// Marshal the next message index to bytes
	nextMessageIndexBytes, err := nextMessageIndex.MarshalBinary()
	if err != nil {
		d.log.Errorf("encryptRead: failed to marshal next message index: %v", err)
		d.sendEncryptReadError(request, thin.ThinClientErrorInternalError)
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		EncryptReadReply: &thin.EncryptReadReply{
			QueryID:            request.EncryptRead.QueryID,
			MessageCiphertext:  courierQuery.Bytes(),
			NextMessageIndex:   nextMessageIndexBytes,
			EnvelopeDescriptor: envelopeDescriptorBytes,
			EnvelopeHash:       envHash,
			ReplicaEpoch:       doc.Epoch,
			ErrorCode:          thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendEncryptReadError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		EncryptReadReply: &thin.EncryptReadReply{
			QueryID:   request.EncryptRead.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// encryptWrite encrypts a write operation for the Pigeonhole protocol.
// This does not perform any mixnet communication, it just prepares the
// encrypted envelope that the thin client will send later.
func (d *Daemon) encryptWrite(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	writeCap := request.EncryptWrite.WriteCap
	if writeCap == nil {
		d.log.Error("encryptWrite: WriteCap is nil")
		d.sendEncryptWriteError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	messageBoxIndex := request.EncryptWrite.MessageBoxIndex
	if messageBoxIndex == nil {
		d.log.Error("encryptWrite: MessageBoxIndex is nil")
		d.sendEncryptWriteError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	plaintext := request.EncryptWrite.Plaintext
	if plaintext == nil {
		d.log.Error("encryptWrite: Plaintext is nil")
		d.sendEncryptWriteError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Create a StatefulWriter from the provided WriteCap and MessageBoxIndex
	statefulWriter, err := bacap.NewStatefulWriterWithIndex(writeCap, constants.PIGEONHOLE_CTX, messageBoxIndex)
	if err != nil {
		d.log.Errorf("encryptWrite: failed to create stateful writer: %v", err)
		d.sendEncryptWriteError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Get the current PKI document
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Error("encryptWrite: no PKI document available")
		d.sendEncryptWriteError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Validate PigeonholeGeometry
	if d.cfg.PigeonholeGeometry == nil {
		d.log.Error("encryptWrite: PigeonholeGeometry is nil")
		d.sendEncryptWriteError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Validate that the payload can fit within the geometry's MaxPlaintextPayloadLength
	// CreatePaddedPayload requires 4 bytes for length prefix plus the payload
	minRequiredSize := len(plaintext) + 4
	if minRequiredSize > d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength+4 {
		d.log.Errorf("encryptWrite: payload too large: %d bytes (+ 4 byte length prefix) exceeds MaxPlaintextPayloadLength + 4 of %d bytes",
			len(plaintext), d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength+4)
		d.sendEncryptWriteError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Pad the payload to the geometry's MaxPlaintextPayloadLength + 4
	paddedPayload, err := pigeonhole.CreatePaddedPayload(plaintext, d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength+4)
	if err != nil {
		d.log.Errorf("encryptWrite: failed to pad payload: %v", err)
		d.sendEncryptWriteError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Encrypt the message WITHOUT advancing state (using PrepareNext)
	boxID, ciphertext, sigraw, err := statefulWriter.PrepareNext(paddedPayload)
	if err != nil {
		d.log.Errorf("encryptWrite: failed to prepare next message: %v", err)
		d.sendEncryptWriteError(request, thin.ThinClientErrorInternalError)
		return
	}

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	// Create the ReplicaWrite message
	writeRequest := &pigeonhole.ReplicaWrite{
		BoxID:      boxID,
		Signature:  sig,
		PayloadLen: uint32(len(ciphertext)),
		Payload:    ciphertext,
	}

	// Create the ReplicaInnerMessage for a write operation
	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg:    writeRequest,
	}

	// Create the envelope using the existing createEnvelopeFromMessage function
	courierEnvelope, envelopePrivateKey, err := createEnvelopeFromMessage(msg, doc, false, 0)
	if err != nil {
		d.log.Errorf("encryptWrite: failed to create envelope: %v", err)
		d.sendEncryptWriteError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Create the EnvelopeDescriptor
	envHash := courierEnvelope.EnvelopeHash()
	envelopeDesc := &EnvelopeDescriptor{
		Epoch:       doc.Epoch,
		ReplicaNums: courierEnvelope.IntermediateReplicas,
		EnvelopeKey: envelopePrivateKey.Bytes(),
	}

	envelopeDescriptorBytes, err := envelopeDesc.Bytes()
	if err != nil {
		d.log.Errorf("encryptWrite: failed to serialize envelope descriptor: %v", err)
		d.sendEncryptWriteError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Create the CourierQuery and serialize it as MessageCiphertext
	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		EncryptWriteReply: &thin.EncryptWriteReply{
			QueryID:            request.EncryptWrite.QueryID,
			MessageCiphertext:  courierQuery.Bytes(),
			ReplicaEpoch:       doc.Epoch,
			EnvelopeDescriptor: envelopeDescriptorBytes,
			EnvelopeHash:       envHash,
			ErrorCode:          thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendEncryptWriteError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		EncryptWriteReply: &thin.EncryptWriteReply{
			QueryID:   request.EncryptWrite.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// createEnvelopeFromMessage creates a CourierEnvelope from a ReplicaInnerMessage
func createEnvelopeFromMessage(msg *pigeonhole.ReplicaInnerMessage, doc *cpki.Document, isRead bool, replyIndex uint8) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {
	var boxid *[bacap.BoxIDSize]byte
	if isRead {
		boxid = &msg.ReadMsg.BoxID
	} else {
		boxid = &msg.WriteMsg.BoxID
	}
	intermediateReplicas, replicaPubKeys, err := pigeonhole.GetRandomIntermediateReplicas(doc, boxid)
	if err != nil {
		return nil, nil, err
	}

	mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes(),
	)
	mkemPublicKey := mkemPrivateKey.Public()

	var dek1, dek2 [60]uint8
	copy(dek1[:], mkemCiphertext.DEKCiphertexts[0][:])
	copy(dek2[:], mkemCiphertext.DEKCiphertexts[1][:])

	senderPubkeyBytes := mkemPublicKey.Bytes()

	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: intermediateReplicas,
		Dek1:                 dek1,
		Dek2:                 dek2,
		ReplyIndex:           replyIndex,
		Epoch:                doc.Epoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}
	return envelope, mkemPrivateKey, nil
}
