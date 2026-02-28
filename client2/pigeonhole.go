// SPDX-FileCopyrightText: (c) 2026  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
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

	// Get the first message index from the WriteCap
	firstIndex := writeCap.GetFirstMessageBoxIndex()

	conn.sendResponse(&Response{
		AppID: request.AppID,
		NewKeypairReply: &thin.NewKeypairReply{
			QueryID:           request.NewKeypair.QueryID,
			WriteCap:          writeCap,
			ReadCap:           readCap,
			FirstMessageIndex: firstIndex,
			ErrorCode:         thin.ThinClientSuccess,
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

	// Get the CURRENT message index (the one we're reading from)
	// This is needed for decryption later - we decrypt using the SAME index we read from
	currentMessageIndex := statefulReader.GetCurrentMessageIndex()
	if currentMessageIndex == nil {
		d.log.Error("encryptRead: current message index is nil")
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

	// Create the EnvelopeDescriptor with replica epoch
	envHash := courierEnvelope.EnvelopeHash()
	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(doc.Epoch)
	envelopeDesc := &EnvelopeDescriptor{
		Epoch:       replicaEpoch,
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

	// Marshal the current message index to bytes
	currentMessageIndexBytes, err := currentMessageIndex.MarshalBinary()
	if err != nil {
		d.log.Errorf("encryptRead: failed to marshal current message index: %v", err)
		d.sendEncryptReadError(request, thin.ThinClientErrorInternalError)
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		EncryptReadReply: &thin.EncryptReadReply{
			QueryID:            request.EncryptRead.QueryID,
			MessageCiphertext:  courierQuery.Bytes(),
			NextMessageIndex:   currentMessageIndexBytes,
			EnvelopeDescriptor: envelopeDescriptorBytes,
			EnvelopeHash:       envHash,
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
	d.log.Debugf("encryptWrite: MessageBoxIndex Idx64=%d, CurBlindingFactor=%x", messageBoxIndex.Idx64, messageBoxIndex.CurBlindingFactor)

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
	d.log.Debugf("encryptWrite: Generated BoxID: %x", boxID)

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

	// Create the EnvelopeDescriptor with replica epoch
	envHash := courierEnvelope.EnvelopeHash()
	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(doc.Epoch)
	envelopeDesc := &EnvelopeDescriptor{
		Epoch:       replicaEpoch,
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

// createCourierEnvelopesFromPayload creates multiple CourierEnvelopes from a payload of any size.
// This is part of the Pigeonhole API to prepare for the Copy Command.
func (d *Daemon) createCourierEnvelopesFromPayload(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	payload := request.CreateCourierEnvelopesFromPayload.Payload
	destWriteCap := request.CreateCourierEnvelopesFromPayload.DestWriteCap
	destStartIndex := request.CreateCourierEnvelopesFromPayload.DestStartIndex

	// Validate inputs
	if destWriteCap == nil {
		d.log.Error("createCourierEnvelopesFromPayload: DestWriteCap is nil")
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	if destStartIndex == nil {
		d.log.Error("createCourierEnvelopesFromPayload: DestStartIndex is nil")
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Enforce 10MB size limit to prevent accidental memory exhaustion
	const maxPayloadSize = 10 * 1024 * 1024 // 10MB
	if len(payload) > maxPayloadSize {
		d.log.Errorf("createCourierEnvelopesFromPayload: payload size %d exceeds maximum of %d bytes (10MB)", len(payload), maxPayloadSize)
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Calculate the maximum user payload size per envelope.
	// We need to leave room for the 4-byte length prefix that CreatePaddedPayload adds.
	maxPayload := d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength - 4
	if maxPayload <= 0 {
		d.log.Error("createCourierEnvelopesFromPayload: invalid geometry, maxPayload <= 0")
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Chunk the payload and create CourierEnvelopes
	var courierEnvelopes []*pigeonhole.CourierEnvelope
	currentIndex := destStartIndex

	for offset := 0; offset < len(payload); offset += maxPayload {
		// Get the chunk
		end := offset + maxPayload
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[offset:end]

		// Pad the chunk to MaxPlaintextPayloadLength + 4 (length prefix is 4 bytes)
		// This must match encryptWrite which also uses MaxPlaintextPayloadLength + 4
		paddedPayload, err := pigeonhole.CreatePaddedPayload(chunk, d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength+4)
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to pad payload: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}

		// Create a StatefulWriter from the destination WriteCap
		statefulWriter, err := bacap.NewStatefulWriter(destWriteCap, []byte(constants.PIGEONHOLE_CTX))
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to create stateful writer: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}

		// Advance the writer to the current message box index
		statefulWriter.NextIndex = currentIndex

		// Encrypt the message using PrepareNext (doesn't advance state)
		boxID, ciphertext, sigraw, err := statefulWriter.PrepareNext(paddedPayload)
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to prepare next message: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
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

		// Get the current PKI document
		_, doc := d.client.CurrentDocument()
		if doc == nil {
			d.log.Error("createCourierEnvelopesFromPayload: no PKI document available")
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}

		// Get random intermediate replicas for this box
		intermediateReplicas, replicaPubKeys, err := pigeonhole.GetRandomIntermediateReplicas(doc, &boxID)
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to get intermediate replicas: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}

		// Encrypt with MKEM to the replica public keys
		mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(
			replicaPubKeys, msg.Bytes(),
		)
		mkemPublicKey := mkemPrivateKey.Public()
		senderPubkey := mkemPublicKey.Bytes()

		// Get the current replica epoch
		replicaEpoch, _, _ := replicaCommon.ReplicaNow()

		// Create the CourierEnvelope
		courierEnvelope := &pigeonhole.CourierEnvelope{
			IntermediateReplicas: intermediateReplicas,
			Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
			Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
			ReplyIndex:           0, // Not used for copy stream writes
			Epoch:                replicaEpoch,
			SenderPubkeyLen:      uint16(len(senderPubkey)),
			SenderPubkey:         senderPubkey,
			CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
			Ciphertext:           mkemCiphertext.Envelope,
		}

		courierEnvelopes = append(courierEnvelopes, courierEnvelope)

		// Advance to the next index
		currentIndex, err = currentIndex.NextIndex()
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to advance index: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}
	}

	// Get or create encoder for this stream
	streamID := request.CreateCourierEnvelopesFromPayload.StreamID
	if streamID == nil {
		d.log.Errorf("createCourierEnvelopesFromPayload: StreamID is required")
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	d.copyStreamEncodersLock.Lock()
	encoder, exists := d.copyStreamEncoders[*streamID]
	if !exists {
		// First call for this stream - create new encoder
		encoder = pigeonhole.NewCopyStreamEncoder(d.cfg.PigeonholeGeometry)
		d.copyStreamEncoders[*streamID] = encoder
	}
	d.copyStreamEncodersLock.Unlock()

	// Encode CourierEnvelopes into copy stream format
	var elements [][]byte
	for _, envelope := range courierEnvelopes {
		newElements, err := encoder.AddEnvelope(envelope)
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to encode envelope: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}
		elements = append(elements, newElements...)
	}

	// If this is the last call, flush and remove encoder
	isLast := request.CreateCourierEnvelopesFromPayload.IsLast
	if isLast {
		finalElements := encoder.Flush()
		if finalElements != nil {
			elements = append(elements, finalElements...)
		}
		// Remove encoder from map
		d.copyStreamEncodersLock.Lock()
		delete(d.copyStreamEncoders, *streamID)
		d.copyStreamEncodersLock.Unlock()
	}

	d.log.Debugf("createCourierEnvelopesFromPayload: created %d CourierEnvelopes, encoded into %d elements (isLast=%v)",
		len(courierEnvelopes), len(elements), isLast)

	// Send success response
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromPayloadReply: &thin.CreateCourierEnvelopesFromPayloadReply{
			QueryID:   request.CreateCourierEnvelopesFromPayload.QueryID,
			Envelopes: elements,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendCreateCourierEnvelopesFromPayloadError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromPayloadReply: &thin.CreateCourierEnvelopesFromPayloadReply{
			QueryID:   request.CreateCourierEnvelopesFromPayload.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// createCourierEnvelopesFromPayloads creates CourierEnvelopes from multiple payloads
// going to different destination channels. This is more space-efficient than calling
// createCourierEnvelopesFromPayload multiple times because all envelopes from all
// destinations are packed together in the same encoder without wasting space.
func (d *Daemon) createCourierEnvelopesFromPayloads(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	destinations := request.CreateCourierEnvelopesFromPayloads.Destinations
	if len(destinations) == 0 {
		d.log.Error("createCourierEnvelopesFromPayloads: no destinations provided")
		d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Calculate the maximum user payload size per envelope.
	// We need to leave room for the 4-byte length prefix that CreatePaddedPayload adds.
	maxPayload := d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength - 4
	if maxPayload <= 0 {
		d.log.Error("createCourierEnvelopesFromPayloads: invalid geometry, maxPayload <= 0")
		d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Get the current PKI document (needed for replica lookup)
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Error("createCourierEnvelopesFromPayloads: no PKI document available")
		d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Get the current replica epoch
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	// Get or create encoder for this stream
	streamID := request.CreateCourierEnvelopesFromPayloads.StreamID
	if streamID == nil {
		d.log.Errorf("createCourierEnvelopesFromPayloads: StreamID is required")
		d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	d.copyStreamEncodersLock.Lock()
	encoder, exists := d.copyStreamEncoders[*streamID]
	if !exists {
		// First call for this stream - create new encoder
		encoder = pigeonhole.NewCopyStreamEncoder(d.cfg.PigeonholeGeometry)
		d.copyStreamEncoders[*streamID] = encoder
	}
	d.copyStreamEncodersLock.Unlock()

	// Process all destinations and feed envelopes into the same encoder
	var elements [][]byte
	totalEnvelopes := 0

	for destIdx, dest := range destinations {
		// Validate destination
		if dest.WriteCap == nil {
			d.log.Errorf("createCourierEnvelopesFromPayloads: destination %d has nil WriteCap", destIdx)
			d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInvalidRequest)
			return
		}
		if dest.StartIndex == nil {
			d.log.Errorf("createCourierEnvelopesFromPayloads: destination %d has nil StartIndex", destIdx)
			d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInvalidRequest)
			return
		}

		// Enforce 10MB size limit per destination
		const maxPayloadSize = 10 * 1024 * 1024 // 10MB
		if len(dest.Payload) > maxPayloadSize {
			d.log.Errorf("createCourierEnvelopesFromPayloads: destination %d payload size %d exceeds maximum of %d bytes", destIdx, len(dest.Payload), maxPayloadSize)
			d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInvalidRequest)
			return
		}

		currentIndex := dest.StartIndex

		// Chunk the payload and create CourierEnvelopes for this destination
		for offset := 0; offset < len(dest.Payload); offset += maxPayload {
			// Get the chunk
			end := offset + maxPayload
			if end > len(dest.Payload) {
				end = len(dest.Payload)
			}
			chunk := dest.Payload[offset:end]

			// Pad the chunk to MaxPlaintextPayloadLength + 4 (length prefix is 4 bytes)
			paddedPayload, err := pigeonhole.CreatePaddedPayload(chunk, d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength+4)
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: failed to pad payload: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
				return
			}

			// Create a StatefulWriter from the destination WriteCap
			statefulWriter, err := bacap.NewStatefulWriter(dest.WriteCap, []byte(constants.PIGEONHOLE_CTX))
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: failed to create stateful writer: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
				return
			}

			// Advance the writer to the current message box index
			statefulWriter.NextIndex = currentIndex

			// Encrypt the message using PrepareNext (doesn't advance state)
			boxID, ciphertext, sigraw, err := statefulWriter.PrepareNext(paddedPayload)
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: failed to prepare next message: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
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

			// Get random intermediate replicas for this box
			intermediateReplicas, replicaPubKeys, err := pigeonhole.GetRandomIntermediateReplicas(doc, &boxID)
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: failed to get intermediate replicas: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
				return
			}

			// Encrypt with MKEM to the replica public keys
			mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(
				replicaPubKeys, msg.Bytes(),
			)
			mkemPublicKey := mkemPrivateKey.Public()
			senderPubkey := mkemPublicKey.Bytes()

			// Create the CourierEnvelope
			courierEnvelope := &pigeonhole.CourierEnvelope{
				IntermediateReplicas: intermediateReplicas,
				Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
				Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
				ReplyIndex:           0, // Not used for copy stream writes
				Epoch:                replicaEpoch,
				SenderPubkeyLen:      uint16(len(senderPubkey)),
				SenderPubkey:         senderPubkey,
				CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
				Ciphertext:           mkemCiphertext.Envelope,
			}

			// Add envelope to encoder immediately (packing efficiently)
			newElements, err := encoder.AddEnvelope(courierEnvelope)
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: failed to encode envelope: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
				return
			}
			elements = append(elements, newElements...)
			totalEnvelopes++

			// Advance to the next index
			currentIndex, err = currentIndex.NextIndex()
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: failed to advance index: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
				return
			}
		}
	}

	// If this is the last call, flush and remove encoder
	isLast := request.CreateCourierEnvelopesFromPayloads.IsLast
	if isLast {
		finalElements := encoder.Flush()
		if finalElements != nil {
			elements = append(elements, finalElements...)
		}
		// Remove encoder from map
		d.copyStreamEncodersLock.Lock()
		delete(d.copyStreamEncoders, *streamID)
		d.copyStreamEncodersLock.Unlock()
	}

	d.log.Debugf("createCourierEnvelopesFromPayloads: created %d CourierEnvelopes from %d destinations, encoded into %d elements (isLast=%v)",
		totalEnvelopes, len(destinations), len(elements), isLast)

	// Send success response
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromPayloadsReply: &thin.CreateCourierEnvelopesFromPayloadsReply{
			QueryID:   request.CreateCourierEnvelopesFromPayloads.QueryID,
			Envelopes: elements,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendCreateCourierEnvelopesFromPayloadsError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromPayloadsReply: &thin.CreateCourierEnvelopesFromPayloadsReply{
			QueryID:   request.CreateCourierEnvelopesFromPayloads.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// nextMessageBoxIndex increments a MessageBoxIndex using the BACAP NextIndex method.
// This is used when sending multiple messages to different mailboxes using the same capability.
func (d *Daemon) nextMessageBoxIndex(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	messageBoxIndex := request.NextMessageBoxIndex.MessageBoxIndex
	if messageBoxIndex == nil {
		d.log.Error("nextMessageBoxIndex: MessageBoxIndex is nil")
		d.sendNextMessageBoxIndexError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Call the BACAP NextIndex method to increment the index
	nextIndex, err := messageBoxIndex.NextIndex()
	if err != nil {
		d.log.Errorf("nextMessageBoxIndex: failed to increment index: %v", err)
		d.sendNextMessageBoxIndexError(request, thin.ThinClientErrorInternalError)
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		NextMessageBoxIndexReply: &thin.NextMessageBoxIndexReply{
			QueryID:             request.NextMessageBoxIndex.QueryID,
			NextMessageBoxIndex: nextIndex,
			ErrorCode:           thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendNextMessageBoxIndexError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		NextMessageBoxIndexReply: &thin.NextMessageBoxIndexReply{
			QueryID:   request.NextMessageBoxIndex.QueryID,
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

	// Convert PKI epoch to replica epoch for the CourierEnvelope
	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(doc.Epoch)

	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: intermediateReplicas,
		Dek1:                 dek1,
		Dek2:                 dek2,
		ReplyIndex:           replyIndex,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}
	return envelope, mkemPrivateKey, nil
}

// startResendingEncryptedMessage starts resending an encrypted Pigeonhole message
// via the ARQ mechanism. It will retry forever until cancelled or successful.
func (d *Daemon) startResendingEncryptedMessage(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	req := request.StartResendingEncryptedMessage
	if req.QueryID == nil {
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	if req.EnvelopeHash == nil {
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	if len(req.MessageCiphertext) == 0 {
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	if len(req.EnvelopeDescriptor) == 0 {
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	// Either ReadCap or WriteCap must be set, but not both
	if (req.ReadCap == nil && req.WriteCap == nil) || (req.ReadCap != nil && req.WriteCap != nil) {
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	isRead := req.ReadCap != nil

	// Get a random Courier
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Errorf("startResendingEncryptedMessage: no PKI document available")
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInternalError)
		return
	}

	destIdHash, recipientQueueID, err := GetRandomCourier(doc)
	if err != nil {
		d.log.Errorf("startResendingEncryptedMessage: failed to get courier: %s", err)
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Create a new SURB ID for this send
	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err = rand.Reader.Read(surbID[:])
	if err != nil {
		d.log.Errorf("startResendingEncryptedMessage: failed to generate SURB ID: %s", err)
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Compose the packet
	pkt, surbKey, rtt, err := d.client.ComposeSphinxPacketForQuery(&thin.SendChannelQuery{
		DestinationIdHash: destIdHash,
		RecipientQueueID:  recipientQueueID,
		Payload:           req.MessageCiphertext,
	}, surbID)
	if err != nil {
		d.log.Errorf("startResendingEncryptedMessage: failed to compose packet: %s", err)
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Create the ARQ message with initial state WaitingForACK
	message := &ARQMessage{
		AppID:              request.AppID,
		QueryID:            req.QueryID,
		EnvelopeHash:       req.EnvelopeHash,
		DestinationIdHash:  destIdHash,
		RecipientQueueID:   recipientQueueID,
		Payload:            req.MessageCiphertext,
		SURBID:             surbID,
		SURBDecryptionKeys: surbKey,
		Retransmissions:    0,
		SentAt:             time.Now(),
		ReplyETA:           rtt,
		EnvelopeDescriptor: req.EnvelopeDescriptor,
		IsRead:             isRead,
		State:              ARQStateWaitingForACK,
		ReadCap:            req.ReadCap,
		NextMessageIndex:   req.NextMessageIndex,
	}

	// Store in ARQ maps
	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = message
	d.arqEnvelopeHashMap[*req.EnvelopeHash] = surbID
	d.replyLock.Unlock()

	// Schedule retry
	myRtt := message.SentAt.Add(message.ReplyETA)
	myRtt = myRtt.Add(RoundTripTimeSlop)
	priority := uint64(myRtt.UnixNano())
	d.arqTimerQueue.Push(priority, surbID)

	// Send the packet
	err = d.client.SendPacket(pkt)
	if err != nil {
		d.log.Errorf("startResendingEncryptedMessage: failed to send packet: %s", err)
		// Don't return error - the ARQ will retry
	}
}

func (d *Daemon) sendStartResendingEncryptedMessageError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
			QueryID:   request.StartResendingEncryptedMessage.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// cancelResendingEncryptedMessage cancels a previously started resend operation.
func (d *Daemon) cancelResendingEncryptedMessage(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	req := request.CancelResendingEncryptedMessage
	if req.QueryID == nil {
		d.sendCancelResendingEncryptedMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	if req.EnvelopeHash == nil {
		d.sendCancelResendingEncryptedMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	d.replyLock.Lock()
	surbID, ok := d.arqEnvelopeHashMap[*req.EnvelopeHash]
	var arqMessage *ARQMessage
	if ok && surbID != nil {
		arqMessage = d.arqSurbIDMap[*surbID]
		delete(d.arqSurbIDMap, *surbID)
		delete(d.arqEnvelopeHashMap, *req.EnvelopeHash)
	}
	d.replyLock.Unlock()

	if !ok {
		d.log.Debugf("cancelResendingEncryptedMessage: EnvelopeHash %x not found", req.EnvelopeHash[:])
		// Still send success - the message may have already completed
	} else if arqMessage != nil {
		// Send cancellation error to the original StartResendingEncryptedMessage call
		d.log.Debugf("cancelResendingEncryptedMessage: Sending cancellation to original query %x", arqMessage.QueryID[:])
		conn.sendResponse(&Response{
			AppID: request.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:   arqMessage.QueryID,
				ErrorCode: thin.ThinClientErrorStartResendingCancelled,
				Plaintext: nil,
			},
		})
	}

	// Send success response to the CancelResendingEncryptedMessage call
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CancelResendingEncryptedMessageReply: &thin.CancelResendingEncryptedMessageReply{
			QueryID:   req.QueryID,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendCancelResendingEncryptedMessageError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CancelResendingEncryptedMessageReply: &thin.CancelResendingEncryptedMessageReply{
			QueryID:   request.CancelResendingEncryptedMessage.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// handlePigeonholeARQReply handles replies to Pigeonhole ARQ messages.
// It implements a finite state machine for the stop-and-wait ARQ protocol:
// - WaitingForACK: Initial state, waiting for ACK from courier
// - ACKReceived: ACK received, for reads we need to send another SURB for payload
// - PayloadReceived: Terminal state for reads after receiving payload
func (d *Daemon) handlePigeonholeARQReply(arqMessage *ARQMessage, reply *sphinxReply) {
	conn := d.listener.getConnection(arqMessage.AppID)
	if conn == nil {
		d.log.Errorf("handlePigeonholeARQReply: no connection for AppID %x", arqMessage.AppID[:])
		return
	}

	// Decrypt the SURB payload
	surbPayload, err := d.client.sphinx.DecryptSURBPayload(reply.ciphertext, arqMessage.SURBDecryptionKeys)
	if err != nil {
		d.log.Errorf("handlePigeonholeARQReply: SURB payload decryption error: %s", err)
		return
	}

	// Parse the CourierQueryReply
	courierQueryReply, err := pigeonhole.ParseCourierQueryReply(surbPayload)
	if err != nil {
		d.log.Errorf("handlePigeonholeARQReply: failed to parse CourierQueryReply: %s", err)
		return
	}

	// Dispatch based on ARQ message type
	switch arqMessage.MessageType {
	case ARQMessageTypeCopyCommand:
		// Handle copy command reply (ReplyType: 1)
		d.handleCopyCommandARQReply(arqMessage, courierQueryReply, conn)
		return
	case ARQMessageTypeEnvelope:
		// Handle envelope reply (type 0) - fall through to existing logic
	default:
		d.log.Errorf("handlePigeonholeARQReply: unknown ARQ message type %d", arqMessage.MessageType)
		return
	}

	// Handle envelope reply (type 0)
	if courierQueryReply.ReplyType != 0 || courierQueryReply.EnvelopeReply == nil {
		d.log.Errorf("handlePigeonholeARQReply: unexpected reply type %d for envelope operation", courierQueryReply.ReplyType)
		return
	}

	courierEnvelopeReply := courierQueryReply.EnvelopeReply

	// Check for error in the reply
	if courierEnvelopeReply.ErrorCode != 0 {
		d.log.Errorf("handlePigeonholeARQReply: courier reply error code %d", courierEnvelopeReply.ErrorCode)
		// Remove from ARQ tracking and send error to thin client
		d.replyLock.Lock()
		delete(d.arqSurbIDMap, *arqMessage.SURBID)
		delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
		d.replyLock.Unlock()

		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:   arqMessage.QueryID,
				ErrorCode: courierEnvelopeReply.ErrorCode,
			},
		})
		return
	}

	// FSM: Handle state transitions based on current state and reply type
	switch arqMessage.State {
	case ARQStateWaitingForACK:
		// We're waiting for an ACK
		if courierEnvelopeReply.ReplyType == pigeonhole.ReplyTypeACK {
			d.log.Debugf("handlePigeonholeARQReply: ACK received for EnvelopeHash %x, IsRead=%v",
				arqMessage.EnvelopeHash[:], arqMessage.IsRead)

			// Transition to ACKReceived state
			arqMessage.State = ARQStateACKReceived

			// For write queries, ACK is the terminal state - we're done
			if !arqMessage.IsRead {
				d.log.Debugf("handlePigeonholeARQReply: Write query complete")
				// Remove from ARQ tracking
				d.replyLock.Lock()
				delete(d.arqSurbIDMap, *arqMessage.SURBID)
				delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
				d.replyLock.Unlock()

				// Send success to thin client
				conn.sendResponse(&Response{
					AppID: arqMessage.AppID,
					StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
						QueryID:   arqMessage.QueryID,
						ErrorCode: thin.ThinClientSuccess,
					},
				})
				return
			}

			// For read queries, we need to send another SURB to get the payload
			// Generate a new SURB and send it to the courier
			d.log.Debugf("handlePigeonholeARQReply: Read query ACK received, sending new SURB for payload")

			// Create a new SURB ID for the payload request
			newSurbID := &[sphinxConstants.SURBIDLength]byte{}
			_, err := rand.Reader.Read(newSurbID[:])
			if err != nil {
				d.log.Errorf("handlePigeonholeARQReply: failed to generate SURB ID for payload: %s", err)
				return
			}

			// Compose a new packet with a new SURB for the payload request
			pkt, surbKey, rtt, err := d.client.ComposeSphinxPacketForQuery(&thin.SendChannelQuery{
				DestinationIdHash: arqMessage.DestinationIdHash,
				RecipientQueueID:  arqMessage.RecipientQueueID,
				Payload:           arqMessage.Payload,
			}, newSurbID)
			if err != nil {
				d.log.Errorf("handlePigeonholeARQReply: failed to compose packet for payload: %s", err)
				return
			}

			// Update ARQ message with new SURB
			d.replyLock.Lock()
			// Remove old SURB ID mapping
			delete(d.arqSurbIDMap, *arqMessage.SURBID)
			// Update message with new SURB
			arqMessage.SURBID = newSurbID
			arqMessage.SURBDecryptionKeys = surbKey
			arqMessage.Retransmissions++
			arqMessage.SentAt = time.Now()
			arqMessage.ReplyETA = rtt
			// Add new SURB ID mapping
			d.arqSurbIDMap[*newSurbID] = arqMessage
			d.replyLock.Unlock()

			// Schedule retry for payload
			myRtt := arqMessage.SentAt.Add(arqMessage.ReplyETA)
			myRtt = myRtt.Add(RoundTripTimeSlop)
			priority := uint64(myRtt.UnixNano())
			d.arqTimerQueue.Push(priority, newSurbID)

			// Send the packet
			err = d.client.SendPacket(pkt)
			if err != nil {
				d.log.Errorf("handlePigeonholeARQReply: failed to send payload request packet: %s", err)
				// Don't return error - the ARQ will retry
			}

			d.log.Debugf("handlePigeonholeARQReply: Sent new SURB for payload, waiting for payload reply")
			return
		} else if courierEnvelopeReply.ReplyType == pigeonhole.ReplyTypePayload {
			// Unexpected: we got payload before ACK
			d.log.Warningf("handlePigeonholeARQReply: Received payload while waiting for ACK")
			// Treat this as if we got both ACK and payload
			arqMessage.State = ARQStatePayloadReceived
			d.handlePayloadReply(arqMessage, courierEnvelopeReply, conn)
			return
		}

	case ARQStateACKReceived:
		// We've received ACK, now waiting for payload (only for reads)
		if courierEnvelopeReply.ReplyType == pigeonhole.ReplyTypePayload {
			d.log.Debugf("handlePigeonholeARQReply: Payload received for EnvelopeHash %x", arqMessage.EnvelopeHash[:])
			arqMessage.State = ARQStatePayloadReceived
			d.handlePayloadReply(arqMessage, courierEnvelopeReply, conn)
			return
		} else if courierEnvelopeReply.ReplyType == pigeonhole.ReplyTypeACK {
			// Duplicate ACK - data not ready yet, keep polling
			d.log.Debugf("handlePigeonholeARQReply: Duplicate ACK received (data not ready), sending new SURB to continue polling")

			// Create a new SURB ID for the next polling request
			newSurbID := &[sphinxConstants.SURBIDLength]byte{}
			_, err := rand.Reader.Read(newSurbID[:])
			if err != nil {
				d.log.Errorf("handlePigeonholeARQReply: failed to generate SURB ID for polling: %s", err)
				return
			}

			// Compose a new packet with a new SURB for the next polling request
			pkt, surbKey, rtt, err := d.client.ComposeSphinxPacketForQuery(&thin.SendChannelQuery{
				DestinationIdHash: arqMessage.DestinationIdHash,
				RecipientQueueID:  arqMessage.RecipientQueueID,
				Payload:           arqMessage.Payload,
			}, newSurbID)
			if err != nil {
				d.log.Errorf("handlePigeonholeARQReply: failed to compose packet for polling: %s", err)
				return
			}

			// Update ARQ message with new SURB
			d.replyLock.Lock()
			// Remove old SURB ID mapping
			delete(d.arqSurbIDMap, *arqMessage.SURBID)
			// Update message with new SURB
			arqMessage.SURBID = newSurbID
			arqMessage.SURBDecryptionKeys = surbKey
			arqMessage.Retransmissions++
			arqMessage.SentAt = time.Now()
			arqMessage.ReplyETA = rtt
			// Add new SURB ID mapping
			d.arqSurbIDMap[*newSurbID] = arqMessage
			d.replyLock.Unlock()

			// Schedule retry for next poll
			myRtt := arqMessage.SentAt.Add(arqMessage.ReplyETA)
			myRtt = myRtt.Add(RoundTripTimeSlop)
			priority := uint64(myRtt.UnixNano())
			d.arqTimerQueue.Push(priority, newSurbID)

			// Send the packet
			err = d.client.SendPacket(pkt)
			if err != nil {
				d.log.Errorf("handlePigeonholeARQReply: failed to send polling packet: %s", err)
				// Don't return error - the ARQ will retry
			}

			d.log.Debugf("handlePigeonholeARQReply: Sent new SURB for continued polling, waiting for payload reply")
			return
		}

	case ARQStatePayloadReceived:
		// Terminal state, shouldn't receive more replies
		d.log.Warningf("handlePigeonholeARQReply: Received reply in terminal state, ignoring")
		return
	}

	d.log.Errorf("handlePigeonholeARQReply: Unexpected state/reply combination: state=%d, replyType=%d",
		arqMessage.State, courierEnvelopeReply.ReplyType)
}

// handleCopyCommandARQReply handles replies to copy command ARQ messages.
// Copy commands have a simple protocol: send command, receive single reply with success/error.
func (d *Daemon) handleCopyCommandARQReply(arqMessage *ARQMessage, courierQueryReply *pigeonhole.CourierQueryReply, conn *incomingConn) {
	// Verify this is a copy command reply (ReplyType: 1)
	if courierQueryReply.ReplyType != 1 || courierQueryReply.CopyCommandReply == nil {
		d.log.Errorf("handleCopyCommandARQReply: expected copy command reply (type 1), got type %d",
			courierQueryReply.ReplyType)
		return
	}

	copyCommandReply := courierQueryReply.CopyCommandReply

	d.log.Debugf("handleCopyCommandARQReply: Received copy command reply, ErrorCode=%d, WriteCapHash=%x",
		copyCommandReply.ErrorCode, arqMessage.EnvelopeHash[:])

	// Remove from ARQ tracking
	d.replyLock.Lock()
	delete(d.arqSurbIDMap, *arqMessage.SURBID)
	delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
	d.replyLock.Unlock()

	// Send reply to thin client
	conn.sendResponse(&Response{
		AppID: arqMessage.AppID,
		StartResendingCopyCommandReply: &thin.StartResendingCopyCommandReply{
			QueryID:   arqMessage.QueryID,
			ErrorCode: copyCommandReply.ErrorCode,
		},
	})
}

// startResendingCopyCommand starts resending a copy command via the ARQ mechanism.
// It will retry forever until cancelled or successful.
func (d *Daemon) startResendingCopyCommand(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	req := request.StartResendingCopyCommand
	if req.QueryID == nil {
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	if req.WriteCap == nil {
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Serialize WriteCap
	writeCapBytes, err := req.WriteCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("startResendingCopyCommand: failed to serialize WriteCap: %s", err)
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Create CopyCommand
	copyCommand := &pigeonhole.CopyCommand{
		WriteCapLen: uint32(len(writeCapBytes)),
		WriteCap:    writeCapBytes,
	}

	// Create CourierQuery with QueryType=1 (copy command)
	courierQuery := &pigeonhole.CourierQuery{
		QueryType:   1, // CopyCommand
		CopyCommand: copyCommand,
	}

	// Serialize to payload
	payload, err := courierQuery.MarshalBinary()
	if err != nil {
		d.log.Errorf("startResendingCopyCommand: failed to serialize CourierQuery: %s", err)
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Compute hash of WriteCap for deduplication/cancellation key
	writeCapHash := hash.Sum256(writeCapBytes)

	// Get courier - use specified courier if provided, otherwise random
	var destIdHash *[32]byte
	var recipientQueueID []byte

	if req.CourierIdentityHash != nil && len(req.CourierQueueID) > 0 {
		// Use the specified courier
		destIdHash = req.CourierIdentityHash
		recipientQueueID = req.CourierQueueID
		d.log.Debugf("startResendingCopyCommand: using specified courier %x", destIdHash[:8])
	} else {
		// Get a random Courier
		_, doc := d.client.CurrentDocument()
		if doc == nil {
			d.log.Errorf("startResendingCopyCommand: no PKI document available")
			d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInternalError)
			return
		}

		var err error
		destIdHash, recipientQueueID, err = GetRandomCourier(doc)
		if err != nil {
			d.log.Errorf("startResendingCopyCommand: failed to get courier: %s", err)
			d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInternalError)
			return
		}
	}

	// Create a new SURB ID for this send
	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err = rand.Reader.Read(surbID[:])
	if err != nil {
		d.log.Errorf("startResendingCopyCommand: failed to generate SURB ID: %s", err)
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Compose the packet
	pkt, surbKey, rtt, err := d.client.ComposeSphinxPacketForQuery(&thin.SendChannelQuery{
		DestinationIdHash: destIdHash,
		RecipientQueueID:  recipientQueueID,
		Payload:           payload,
	}, surbID)
	if err != nil {
		d.log.Errorf("startResendingCopyCommand: failed to compose packet: %s", err)
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Create the ARQ message for copy command
	message := &ARQMessage{
		MessageType:        ARQMessageTypeCopyCommand,
		AppID:              request.AppID,
		QueryID:            req.QueryID,
		EnvelopeHash:       &writeCapHash, // Use WriteCap hash as envelope hash for dedup
		DestinationIdHash:  destIdHash,
		RecipientQueueID:   recipientQueueID,
		Payload:            payload,
		SURBID:             surbID,
		SURBDecryptionKeys: surbKey,
		Retransmissions:    0,
		SentAt:             time.Now(),
		ReplyETA:           rtt,
		State:              ARQStateWaitingForACK, // Only one state for copy commands
	}

	// Store in ARQ maps
	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = message
	d.arqEnvelopeHashMap[writeCapHash] = surbID
	d.replyLock.Unlock()

	// Schedule retry
	myRtt := message.SentAt.Add(message.ReplyETA)
	myRtt = myRtt.Add(RoundTripTimeSlop)
	priority := uint64(myRtt.UnixNano())
	d.arqTimerQueue.Push(priority, surbID)

	d.log.Debugf("startResendingCopyCommand: Sending copy command, QueryID=%x, WriteCapHash=%x",
		req.QueryID[:], writeCapHash[:])

	// Send the packet
	err = d.client.SendPacket(pkt)
	if err != nil {
		d.log.Errorf("startResendingCopyCommand: failed to send packet: %s", err)
		// Don't return error - the ARQ will retry
	}
}

func (d *Daemon) sendStartResendingCopyCommandError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		StartResendingCopyCommandReply: &thin.StartResendingCopyCommandReply{
			QueryID:   request.StartResendingCopyCommand.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// cancelResendingCopyCommand cancels a previously started copy command resend operation.
func (d *Daemon) cancelResendingCopyCommand(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	req := request.CancelResendingCopyCommand
	if req.QueryID == nil {
		d.sendCancelResendingCopyCommandError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	if req.WriteCapHash == nil {
		d.sendCancelResendingCopyCommandError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Look up SURB ID from EnvelopeHash map (using WriteCapHash as the key)
	d.replyLock.Lock()
	surbID, ok := d.arqEnvelopeHashMap[*req.WriteCapHash]
	var arqMessage *ARQMessage
	if ok && surbID != nil {
		arqMessage = d.arqSurbIDMap[*surbID]
		delete(d.arqSurbIDMap, *surbID)
		delete(d.arqEnvelopeHashMap, *req.WriteCapHash)
	}
	d.replyLock.Unlock()

	if !ok {
		d.log.Debugf("cancelResendingCopyCommand: WriteCapHash %x not found", req.WriteCapHash[:])
		// Still send success - the message may have already completed
	} else if arqMessage != nil {
		// Send cancellation error to the original StartResendingCopyCommand call
		d.log.Debugf("cancelResendingCopyCommand: Sending cancellation to original query %x", arqMessage.QueryID[:])
		conn.sendResponse(&Response{
			AppID: request.AppID,
			StartResendingCopyCommandReply: &thin.StartResendingCopyCommandReply{
				QueryID:   arqMessage.QueryID,
				ErrorCode: thin.ThinClientErrorStartResendingCancelled,
			},
		})
	}

	// Send success response to the CancelResendingCopyCommand call
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CancelResendingCopyCommandReply: &thin.CancelResendingCopyCommandReply{
			QueryID:   req.QueryID,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendCancelResendingCopyCommandError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CancelResendingCopyCommandReply: &thin.CancelResendingCopyCommandReply{
			QueryID:   request.CancelResendingCopyCommand.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// handlePayloadReply processes a payload reply and sends it to the thin client.
func (d *Daemon) handlePayloadReply(arqMessage *ARQMessage, courierEnvelopeReply *pigeonhole.CourierEnvelopeReply, conn *incomingConn) {
	plaintext, err := d.decryptPigeonholeReply(arqMessage, courierEnvelopeReply)
	if err != nil {
		d.log.Errorf("handlePayloadReply: failed to decrypt reply: %s", err)

		// Remove from ARQ tracking for all error cases
		d.replyLock.Lock()
		delete(d.arqSurbIDMap, *arqMessage.SURBID)
		delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
		d.replyLock.Unlock()

		// Determine the specific error type
		var errorCode uint8
		switch {
		case errors.Is(err, errMKEMDecryptionFailed):
			// MKEM decryption failed
			d.log.Debugf("handlePayloadReply: MKEM decryption failed")
			errorCode = thin.ThinClientErrorMKEMDecryptionFailed
		case errors.Is(err, errBACAPDecryptionFailed):
			// BACAP decryption failed
			d.log.Debugf("handlePayloadReply: BACAP decryption failed")
			errorCode = thin.ThinClientErrorBACAPDecryptionFailed
		default:
			// Check if this is a replica error (with error code)
			var re *replicaError
			if errors.As(err, &re) {
				// Replica error - use the exact error code from the replica
				d.log.Debugf("handlePayloadReply: Replica error code %d", re.code)
				errorCode = re.code
			} else {
				// Other decryption or internal error
				d.log.Debugf("handlePayloadReply: Other error: %v", err)
				errorCode = thin.ThinClientErrorInternalError
			}
		}

		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:   arqMessage.QueryID,
				ErrorCode: errorCode,
			},
		})
		return
	}

	// Remove from ARQ tracking
	d.replyLock.Lock()
	delete(d.arqSurbIDMap, *arqMessage.SURBID)
	delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
	d.replyLock.Unlock()

	// Unpad the plaintext (remove length prefix and padding)
	unpaddedPlaintext, err := pigeonhole.ExtractMessageFromPaddedPayload(plaintext)
	if err != nil {
		d.log.Errorf("handlePayloadReply: Failed to unpad plaintext: %v", err)
		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:   arqMessage.QueryID,
				ErrorCode: thin.ThinClientErrorInternalError,
			},
		})
		return
	}

	// Send success with unpadded plaintext to thin client
	conn.sendResponse(&Response{
		AppID: arqMessage.AppID,
		StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
			QueryID:   arqMessage.QueryID,
			Plaintext: unpaddedPlaintext,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

// decryptPigeonholeReply decrypts the Pigeonhole envelope reply using the stored EnvelopeDescriptor.
func (d *Daemon) decryptPigeonholeReply(arqMessage *ARQMessage, env *pigeonhole.CourierEnvelopeReply) ([]byte, error) {
	d.log.Debugf("decryptPigeonholeReply: Starting decryption, env.Payload length: %d", len(env.Payload))

	// Deserialize the EnvelopeDescriptor
	envelopeDesc, err := EnvelopeDescriptorFromBytes(arqMessage.EnvelopeDescriptor)
	if err != nil {
		d.log.Errorf("decryptPigeonholeReply: Failed to deserialize EnvelopeDescriptor: %v", err)
		return nil, err
	}
	d.log.Debugf("decryptPigeonholeReply: EnvelopeDescriptor deserialized, ReplicaNums: %v", envelopeDesc.ReplicaNums)

	// Reconstruct the NIKE private key
	privateKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPrivateKey(envelopeDesc.EnvelopeKey)
	if err != nil {
		d.log.Errorf("decryptPigeonholeReply: Failed to unmarshal private key: %v", err)
		return nil, err
	}
	d.log.Debugf("decryptPigeonholeReply: Private key reconstructed")

	// Reuse the existing decryptMKEMEnvelope function
	innerMsg, err := d.decryptMKEMEnvelope(env, envelopeDesc, privateKey)
	if err != nil {
		d.log.Errorf("decryptPigeonholeReply: Failed to decrypt MKEM envelope: %v", err)
		return nil, err
	}
	d.log.Debugf("decryptPigeonholeReply: MKEM envelope decrypted, MessageType: %d", innerMsg.MessageType)

	// Handle read reply
	if innerMsg.MessageType == 0 && innerMsg.ReadReply != nil {
		d.log.Debugf("decryptPigeonholeReply: Processing read reply, ErrorCode: %d, Payload length: %d",
			innerMsg.ReadReply.ErrorCode, len(innerMsg.ReadReply.Payload))
		if innerMsg.ReadReply.ErrorCode != 0 {
			// Return a structured error with the replica error code
			return nil, &replicaError{code: innerMsg.ReadReply.ErrorCode}
		}

		// Perform BACAP decryption if this is a read operation
		if arqMessage.IsRead && arqMessage.ReadCap != nil && arqMessage.NextMessageIndex != nil {
			d.log.Debugf("decryptPigeonholeReply: Performing BACAP decryption")

			// Deserialize the NextMessageIndex
			messageBoxIndex, err := bacap.NewEmptyMessageBoxIndexFromBytes(arqMessage.NextMessageIndex)
			if err != nil {
				d.log.Errorf("decryptPigeonholeReply: Failed to deserialize MessageBoxIndex: %v", err)
				return nil, fmt.Errorf("%w: failed to deserialize MessageBoxIndex: %v", errBACAPDecryptionFailed, err)
			}

			// Create a StatefulReader from the ReadCap and NextMessageIndex
			statefulReader, err := bacap.NewStatefulReaderWithIndex(arqMessage.ReadCap, constants.PIGEONHOLE_CTX, messageBoxIndex)
			if err != nil {
				d.log.Errorf("decryptPigeonholeReply: Failed to create StatefulReader: %v", err)
				return nil, fmt.Errorf("%w: failed to create StatefulReader: %v", errBACAPDecryptionFailed, err)
			}

			// Calculate the expected BoxID from the ReadCap and MessageBoxIndex
			expectedBoxID := messageBoxIndex.BoxIDForContext(arqMessage.ReadCap, constants.PIGEONHOLE_CTX)
			d.log.Errorf("decryptPigeonholeReply: BoxID comparison - Expected: %x, Got from replica: %x",
				expectedBoxID.Bytes(), innerMsg.ReadReply.BoxID)

			// Decrypt the BACAP payload
			signature := (*[bacap.SignatureSize]byte)(innerMsg.ReadReply.Signature[:])
			plaintext, err := statefulReader.DecryptNext(
				[]byte(constants.PIGEONHOLE_CTX),
				innerMsg.ReadReply.BoxID,
				innerMsg.ReadReply.Payload,
				*signature)
			if err != nil {
				d.log.Errorf("decryptPigeonholeReply: BACAP decryption failed: %v", err)
				return nil, fmt.Errorf("%w: %v", errBACAPDecryptionFailed, err)
			}

			d.log.Debugf("decryptPigeonholeReply: BACAP decryption successful, plaintext length: %d", len(plaintext))
			return plaintext, nil
		}

		// If not a read operation, return the MKEM-decrypted payload as-is
		d.log.Debugf("decryptPigeonholeReply: Returning MKEM-decrypted payload of length %d", len(innerMsg.ReadReply.Payload))
		return innerMsg.ReadReply.Payload, nil
	}

	d.log.Errorf("decryptPigeonholeReply: Unexpected inner message type: %d", innerMsg.MessageType)
	return nil, fmt.Errorf("unexpected inner message type: %d", innerMsg.MessageType)
}
