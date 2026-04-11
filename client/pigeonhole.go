// SPDX-FileCopyrightText: (c) 2026  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
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
	d.log.Debugf("encryptRead: Idx64=%d, BoxID=%x", messageBoxIndex.Idx64, boxID)

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

	// Create the envelope with padding so reads are indistinguishable from writes
	courierEnvelope, envelopePrivateKey, err := createEnvelopeFromMessageWithPadding(msg, doc, true, 0, d.cfg.PigeonholeGeometry)
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

	// Compute the next message box index
	nextMessageBoxIndex, err := messageBoxIndex.NextIndex()
	if err != nil {
		d.log.Errorf("encryptRead: failed to compute next index: %v", err)
		d.sendEncryptReadError(request, thin.ThinClientErrorInternalError)
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		EncryptReadReply: &thin.EncryptReadReply{
			QueryID:             request.EncryptRead.QueryID,
			MessageCiphertext:   courierQuery.Bytes(),
			EnvelopeDescriptor:  envelopeDescriptorBytes,
			EnvelopeHash:        envHash,
			NextMessageBoxIndex: nextMessageBoxIndex,
			ErrorCode:           thin.ThinClientSuccess,
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

	var boxID [bacap.BoxIDSize]byte
	var sig [bacap.SignatureSize]byte
	var ciphertext []byte

	// Check if this is a tombstone (zero-length plaintext)
	if len(plaintext) == 0 {
		d.log.Debug("encryptWrite: Detected tombstone (zero-length plaintext)")

		// For tombstones, we sign an empty payload without encryption
		var sigraw []byte
		boxID, sigraw = messageBoxIndex.SignBox(writeCap, constants.PIGEONHOLE_CTX, []byte{})
		copy(sig[:], sigraw)
		ciphertext = nil // Empty payload for tombstone
		d.log.Debugf("encryptWrite: Generated tombstone BoxID: %x, Idx64=%d", boxID, messageBoxIndex.Idx64)
	} else {
		// Normal write path: validate size, pad, and encrypt

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

		// Create a StatefulWriter from the provided WriteCap and MessageBoxIndex
		statefulWriter, err := bacap.NewStatefulWriterWithIndex(writeCap, constants.PIGEONHOLE_CTX, messageBoxIndex)
		if err != nil {
			d.log.Errorf("encryptWrite: failed to create stateful writer: %v", err)
			d.sendEncryptWriteError(request, thin.ThinClientErrorInternalError)
			return
		}

		// Encrypt the message WITHOUT advancing state (using PrepareNext)
		var sigraw []byte
		boxID, ciphertext, sigraw, err = statefulWriter.PrepareNext(paddedPayload)
		if err != nil {
			d.log.Errorf("encryptWrite: failed to prepare next message: %v", err)
			d.sendEncryptWriteError(request, thin.ThinClientErrorInternalError)
			return
		}
		d.log.Debugf("encryptWrite: Generated BoxID: %x, Idx64=%d", boxID, messageBoxIndex.Idx64)
		copy(sig[:], sigraw)
	}

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

	// Create the envelope with padding so tombstones are indistinguishable from normal writes
	courierEnvelope, envelopePrivateKey, err := createEnvelopeFromMessageWithPadding(msg, doc, false, 0, d.cfg.PigeonholeGeometry)
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

	// Compute the next message box index
	nextMessageBoxIndex, err := messageBoxIndex.NextIndex()
	if err != nil {
		d.log.Errorf("encryptWrite: failed to compute next index: %v", err)
		d.sendEncryptWriteError(request, thin.ThinClientErrorInternalError)
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		EncryptWriteReply: &thin.EncryptWriteReply{
			QueryID:             request.EncryptWrite.QueryID,
			MessageCiphertext:   courierQuery.Bytes(),
			EnvelopeDescriptor:  envelopeDescriptorBytes,
			EnvelopeHash:        envHash,
			NextMessageBoxIndex: nextMessageBoxIndex,
			ErrorCode:           thin.ThinClientSuccess,
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
// chunkPayload splits a payload into chunks of at most maxChunkSize bytes.
func chunkPayload(payload []byte, maxChunkSize int) [][]byte {
	if len(payload) == 0 {
		return nil
	}
	var chunks [][]byte
	for offset := 0; offset < len(payload); offset += maxChunkSize {
		end := offset + maxChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunks = append(chunks, payload[offset:end])
	}
	return chunks
}

// validateEnvelopePayloadRequest validates inputs for createCourierEnvelopesFromPayload.
// maxPlaintextPayloadLength is the geometry's MaxPlaintextPayloadLength.
func validateEnvelopePayloadRequest(payload []byte, writeCap *bacap.WriteCap, startIndex *bacap.MessageBoxIndex, maxPlaintextPayloadLength int) error {
	if writeCap == nil {
		return fmt.Errorf("DestWriteCap is nil")
	}
	if startIndex == nil {
		return fmt.Errorf("DestStartIndex is nil")
	}
	const maxPayloadSize = 10 * 1024 * 1024
	if len(payload) > maxPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum of %d bytes", len(payload), maxPayloadSize)
	}
	maxPayload := maxPlaintextPayloadLength - 4
	if maxPayload <= 0 {
		return fmt.Errorf("invalid geometry, maxPayload <= 0")
	}
	return nil
}

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
	if err := validateEnvelopePayloadRequest(payload, destWriteCap, destStartIndex, d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength); err != nil {
		d.log.Errorf("createCourierEnvelopesFromPayload: %v", err)
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Enforce 10MB size limit
	const maxPayloadSize = 10 * 1024 * 1024
	if len(payload) > maxPayloadSize {
		d.log.Errorf("createCourierEnvelopesFromPayload: payload size %d exceeds maximum of %d bytes", len(payload), maxPayloadSize)
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	maxPayload := d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength - 4
	chunks := chunkPayload(payload, maxPayload)

	// Fetch PKI document once before the loop
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Error("createCourierEnvelopesFromPayload: no PKI document available")
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
		return
	}

	// Get replica epoch once before the loop
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	// Create a single StatefulWriter for the destination
	statefulWriter, err := bacap.NewStatefulWriter(destWriteCap, []byte(constants.PIGEONHOLE_CTX))
	if err != nil {
		d.log.Errorf("createCourierEnvelopesFromPayload: failed to create stateful writer: %v", err)
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
		return
	}
	statefulWriter.NextIndex = destStartIndex

	// Create CourierEnvelopes from chunks
	var courierEnvelopes []*pigeonhole.CourierEnvelope

	for _, chunk := range chunks {
		// Pad the chunk to MaxPlaintextPayloadLength + 4 (length prefix is 4 bytes)
		// This must match encryptWrite which also uses MaxPlaintextPayloadLength + 4
		paddedPayload, err := pigeonhole.CreatePaddedPayload(chunk, d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength+4)
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to pad payload: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}

		// Encrypt the message and advance the writer state
		boxID, ciphertext, sigraw, err := statefulWriter.EncryptNext(paddedPayload)
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to encrypt next message: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}
		d.log.Debugf("createCourierEnvelopesFromPayload: BoxID=%x", boxID)

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
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to get intermediate replicas: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}

		// Pad and encrypt with MKEM to the replica public keys
		paddedMsg, err := pigeonhole.PadInnerMessageForEncryption(msg, d.cfg.PigeonholeGeometry)
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to pad inner message: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}
		mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(
			replicaPubKeys, paddedMsg,
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

		courierEnvelopes = append(courierEnvelopes, courierEnvelope)
	}

	// Stateless: create a fresh encoder, encode, flush in one shot
	isStart := request.CreateCourierEnvelopesFromPayload.IsStart
	isLast := request.CreateCourierEnvelopesFromPayload.IsLast
	encoder := pigeonhole.NewCopyStreamEncoder(d.cfg.PigeonholeGeometry)

	// If this is not the first call in the stream, suppress the auto-isStart
	if !isStart {
		encoder.SuppressStart()
	}

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

	// Always flush — stateless, no buffering across calls
	if isLast {
		finalElements := encoder.Flush()
		if finalElements != nil {
			elements = append(elements, finalElements...)
		}
	} else {
		finalElements := encoder.FlushWithoutFinal()
		if finalElements != nil {
			elements = append(elements, finalElements...)
		}
	}

	// NextDestIndex is the writer's current NextIndex after processing all chunks
	nextDestIndex := statefulWriter.NextIndex

	d.log.Debugf("createCourierEnvelopesFromPayload: created %d CourierEnvelopes, encoded into %d elements (isStart=%v, isLast=%v)",
		len(courierEnvelopes), len(elements), isStart, isLast)

	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromPayloadReply: &thin.CreateCourierEnvelopesFromPayloadReply{
			QueryID:       request.CreateCourierEnvelopesFromPayload.QueryID,
			Envelopes:     elements,
			NextDestIndex: nextDestIndex,
			ErrorCode:     thin.ThinClientSuccess,
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
	nextDestIndices := make([]*bacap.MessageBoxIndex, len(destinations))

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
			d.log.Debugf("createCourierEnvelopesFromPayloads: dest=%d, Idx64=%d, BoxID=%x", destIdx, currentIndex.Idx64, boxID)

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

			// Pad and encrypt with MKEM to the replica public keys
			paddedMsg, err := pigeonhole.PadInnerMessageForEncryption(msg, d.cfg.PigeonholeGeometry)
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: failed to pad inner message: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
				return
			}
			mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(
				replicaPubKeys, paddedMsg,
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
		nextDestIndices[destIdx] = currentIndex
	}

	// If this is the last call, flush and remove encoder
	isLast := request.CreateCourierEnvelopesFromPayloads.IsLast
	var bufferState *pigeonhole.CopyStreamEncoderState
	if isLast {
		finalElements := encoder.Flush()
		if finalElements != nil {
			elements = append(elements, finalElements...)
		}
		// Remove encoder from map
		d.copyStreamEncodersLock.Lock()
		delete(d.copyStreamEncoders, *streamID)
		d.copyStreamEncodersLock.Unlock()
		// Buffer is empty after flush
		bufferState = &pigeonhole.CopyStreamEncoderState{
			Buffer: nil,
		}
	} else {
		// Get the current buffer state for crash recovery
		bufferState = encoder.GetBuffer()
	}

	d.log.Debugf("createCourierEnvelopesFromPayloads: created %d CourierEnvelopes from %d destinations, encoded into %d elements (isLast=%v, bufferLen=%d)",
		totalEnvelopes, len(destinations), len(elements), isLast, len(bufferState.Buffer))

	// Send success response with buffer state for crash recovery
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromPayloadsReply: &thin.CreateCourierEnvelopesFromPayloadsReply{
			QueryID:         request.CreateCourierEnvelopesFromPayloads.QueryID,
			Envelopes:       elements,
			Buffer:          bufferState.Buffer,
			NextDestIndices: nextDestIndices,
			ErrorCode:       thin.ThinClientSuccess,
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

// setStreamBuffer restores the buffered state for a given stream ID.
// This is useful for crash recovery: after restart, the thin client calls this
// with the buffer state that was returned by CreateCourierEnvelopesFromPayload(s)
// before the crash/shutdown.
func (d *Daemon) setStreamBuffer(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	streamID := request.SetStreamBuffer.StreamID
	if streamID == nil {
		d.log.Errorf("setStreamBuffer: StreamID is required")
		d.sendSetStreamBufferError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	// Create the state to restore
	state := &pigeonhole.CopyStreamEncoderState{
		Buffer: request.SetStreamBuffer.Buffer,
	}

	d.copyStreamEncodersLock.Lock()
	encoder, exists := d.copyStreamEncoders[*streamID]
	if !exists {
		// Create a new encoder for this stream
		encoder = pigeonhole.NewCopyStreamEncoder(d.cfg.PigeonholeGeometry)
		d.copyStreamEncoders[*streamID] = encoder
	}
	// Restore the state
	encoder.SetBuffer(state)
	d.copyStreamEncodersLock.Unlock()

	d.log.Debugf("setStreamBuffer: restored buffer for stream %x (bufferLen=%d, newEncoder=%v)",
		streamID[:], len(state.Buffer), !exists)

	conn.sendResponse(&Response{
		AppID: request.AppID,
		SetStreamBufferReply: &thin.SetStreamBufferReply{
			QueryID:   request.SetStreamBuffer.QueryID,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendSetStreamBufferError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		SetStreamBufferReply: &thin.SetStreamBufferReply{
			QueryID:   request.SetStreamBuffer.QueryID,
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
	d.log.Debugf("nextMessageBoxIndex: advanced from Idx64=%d to Idx64=%d", messageBoxIndex.Idx64, nextIndex.Idx64)

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
	return createEnvelopeFromMessageWithPadding(msg, doc, isRead, replyIndex, nil)
}

func createEnvelopeFromMessageWithPadding(msg *pigeonhole.ReplicaInnerMessage, doc *cpki.Document, isRead bool, replyIndex uint8, geo *pigeonholeGeo.Geometry) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {
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

	// Pad the inner message to the write size so tombstones are
	// indistinguishable from normal writes. If geo is nil, no padding is applied.
	var msgBytes []byte
	if geo != nil {
		msgBytes, err = pigeonhole.PadInnerMessageForEncryption(msg, geo)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to pad inner message: %w", err)
		}
	} else {
		msgBytes = msg.Bytes()
	}

	mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(
		replicaPubKeys, msgBytes,
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
// validateStartResendingRequest validates the fields of a StartResendingEncryptedMessage request.
func validateStartResendingRequest(req *thin.StartResendingEncryptedMessage) error {
	if req.QueryID == nil {
		return fmt.Errorf("QueryID is nil")
	}
	if req.EnvelopeHash == nil {
		return fmt.Errorf("EnvelopeHash is nil")
	}
	if len(req.MessageCiphertext) == 0 {
		return fmt.Errorf("MessageCiphertext is empty")
	}
	if len(req.EnvelopeDescriptor) == 0 {
		return fmt.Errorf("EnvelopeDescriptor is empty")
	}
	if (req.ReadCap == nil && req.WriteCap == nil) || (req.ReadCap != nil && req.WriteCap != nil) {
		return fmt.Errorf("exactly one of ReadCap or WriteCap must be set")
	}
	return nil
}

func (d *Daemon) startResendingEncryptedMessage(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	req := request.StartResendingEncryptedMessage
	if err := validateStartResendingRequest(req); err != nil {
		d.log.Errorf("startResendingEncryptedMessage: %v", err)
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	isRead := req.ReadCap != nil

	// Log the box ID (blinded ed25519 public key) for debugging
	var boxIDHex string = "<unknown>"
	var idx64Str string = "<unknown>"
	if len(req.MessageBoxIndex) > 0 {
		if mbi, err := bacap.NewEmptyMessageBoxIndexFromBytes(req.MessageBoxIndex); err == nil {
			idx64Str = fmt.Sprintf("%d", mbi.Idx64)
			if isRead && req.ReadCap != nil {
				boxID := req.ReadCap.DeriveBoxID(mbi)
				boxIDHex = fmt.Sprintf("%x", boxID.Bytes())
			} else if !isRead && req.WriteCap != nil {
				boxID := req.WriteCap.DeriveBoxID(mbi)
				boxIDHex = fmt.Sprintf("%x", boxID.Bytes())
			}
		}
	}
	d.log.Debugf("startResendingEncryptedMessage: isRead=%v, Idx64=%s, boxID=%s, NoRetryOnBoxIDNotFound=%v, NoIdempotentBoxAlreadyExists=%v, EnvelopeHash=%x",
		isRead, idx64Str, boxIDHex, req.NoRetryOnBoxIDNotFound, req.NoIdempotentBoxAlreadyExists, req.EnvelopeHash[:])

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
		AppID:                        request.AppID,
		QueryID:                      req.QueryID,
		EnvelopeHash:                 req.EnvelopeHash,
		DestinationIdHash:            destIdHash,
		RecipientQueueID:             recipientQueueID,
		Payload:                      req.MessageCiphertext,
		SURBID:                       surbID,
		SURBDecryptionKeys:           surbKey,
		Retransmissions:              0,
		SentAt:                       time.Now(),
		ReplyETA:                     rtt,
		EnvelopeDescriptor:           req.EnvelopeDescriptor,
		IsRead:                       isRead,
		State:                        ARQStateWaitingForACK,
		ReadCap:                      req.ReadCap,
		MessageBoxIndex:              req.MessageBoxIndex,
		NoRetryOnBoxIDNotFound:       req.NoRetryOnBoxIDNotFound,
		NoIdempotentBoxAlreadyExists: req.NoIdempotentBoxAlreadyExists,
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
				QueryID:             arqMessage.QueryID,
				ErrorCode:           thin.ThinClientErrorStartResendingCancelled,
				Plaintext:           nil,
				CourierIdentityHash: arqMessage.DestinationIdHash,
				CourierQueueID:      arqMessage.RecipientQueueID,
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

	// Log all state for debugging
	d.log.Debugf("handlePigeonholeARQReply: EnvelopeHash=%x, State=%d, ReplyType=%d, PayloadLen=%d, ErrorCode=%d, IsRead=%v",
		arqMessage.EnvelopeHash[:], arqMessage.State, courierEnvelopeReply.ReplyType, courierEnvelopeReply.PayloadLen, courierEnvelopeReply.ErrorCode, arqMessage.IsRead)

	// Use the pure FSM to determine the action
	transition := computeARQStateTransition(
		arqMessage.State,
		courierEnvelopeReply.ReplyType,
		courierEnvelopeReply.ErrorCode,
		arqMessage.IsRead,
		arqMessage.NoIdempotentBoxAlreadyExists,
	)

	d.log.Debugf("handlePigeonholeARQReply: FSM transition: state=%d replyType=%d → action=%d newState=%d",
		arqMessage.State, courierEnvelopeReply.ReplyType, transition.Action, transition.NewState)

	switch transition.Action {
	case ARQActionError:
		d.log.Errorf("handlePigeonholeARQReply: courier reply error code %d", transition.ErrorCode)
		d.replyLock.Lock()
		delete(d.arqSurbIDMap, *arqMessage.SURBID)
		delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
		d.replyLock.Unlock()

		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:             arqMessage.QueryID,
				ErrorCode:           transition.ErrorCode,
				CourierIdentityHash: arqMessage.DestinationIdHash,
				CourierQueueID:      arqMessage.RecipientQueueID,
			},
		})
		return

	case ARQActionComplete:
		d.log.Debugf("handlePigeonholeARQReply: Write ACK received, returning success (single round-trip)")
		d.replyLock.Lock()
		delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
		d.replyLock.Unlock()

		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:             arqMessage.QueryID,
				ErrorCode:           thin.ThinClientSuccess,
				CourierIdentityHash: arqMessage.DestinationIdHash,
				CourierQueueID:      arqMessage.RecipientQueueID,
			},
		})
		return

	case ARQActionHandlePayload:
		arqMessage.State = transition.NewState
		d.handlePayloadReply(arqMessage, courierEnvelopeReply, conn)
		return

	case ARQActionSendNewSURB:
		arqMessage.State = transition.NewState
		d.log.Debugf("handlePigeonholeARQReply: sending new SURB (isRead=%v, state=%d)",
			arqMessage.IsRead, arqMessage.State)

		newSurbID := &[sphinxConstants.SURBIDLength]byte{}
		_, err := rand.Reader.Read(newSurbID[:])
		if err != nil {
			d.log.Errorf("handlePigeonholeARQReply: failed to generate SURB ID: %s", err)
			return
		}

		pkt, surbKey, rtt, err := d.client.ComposeSphinxPacketForQuery(&thin.SendChannelQuery{
			DestinationIdHash: arqMessage.DestinationIdHash,
			RecipientQueueID:  arqMessage.RecipientQueueID,
			Payload:           arqMessage.Payload,
		}, newSurbID)
		if err != nil {
			d.log.Errorf("handlePigeonholeARQReply: failed to compose packet: %s", err)
			return
		}

		d.replyLock.Lock()
		delete(d.arqSurbIDMap, *arqMessage.SURBID)
		if d.listener.getConnection(arqMessage.AppID) == nil {
			d.replyLock.Unlock()
			d.log.Debugf("handlePigeonholeARQReply: connection gone for AppID %x, dropping ARQ for EnvelopeHash %x", arqMessage.AppID[:], arqMessage.EnvelopeHash[:])
			return
		}
		arqMessage.SURBID = newSurbID
		arqMessage.SURBDecryptionKeys = surbKey
		arqMessage.Retransmissions++
		arqMessage.SentAt = time.Now()
		arqMessage.ReplyETA = rtt
		d.arqSurbIDMap[*newSurbID] = arqMessage
		d.replyLock.Unlock()

		myRtt := arqMessage.SentAt.Add(arqMessage.ReplyETA)
		myRtt = myRtt.Add(RoundTripTimeSlop)
		priority := uint64(myRtt.UnixNano())
		d.arqTimerQueue.Push(priority, newSurbID)

		err = d.client.SendPacket(pkt)
		if err != nil {
			d.log.Errorf("handlePigeonholeARQReply: failed to send packet: %s", err)
		}
		return

	case ARQActionIgnore:
		d.log.Warningf("handlePigeonholeARQReply: Received reply in terminal state, ignoring")
		return
	}
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

// validateStartResendingCopyCommandRequest validates the fields of a StartResendingCopyCommand request.
func validateStartResendingCopyCommandRequest(req *thin.StartResendingCopyCommand) error {
	if req.QueryID == nil {
		return fmt.Errorf("QueryID is nil")
	}
	if req.WriteCap == nil {
		return fmt.Errorf("WriteCap is nil")
	}
	return nil
}

// validateCancelResendingCopyCommandRequest validates the fields of a CancelResendingCopyCommand request.
func validateCancelResendingCopyCommandRequest(req *thin.CancelResendingCopyCommand) error {
	if req.QueryID == nil {
		return fmt.Errorf("QueryID is nil")
	}
	if req.WriteCapHash == nil {
		return fmt.Errorf("WriteCapHash is nil")
	}
	return nil
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
	if err := validateStartResendingCopyCommandRequest(req); err != nil {
		d.log.Errorf("startResendingCopyCommand: %v", err)
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
	if err := validateCancelResendingCopyCommandRequest(req); err != nil {
		d.log.Errorf("cancelResendingCopyCommand: %v", err)
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

// payloadErrorAction represents the action to take when a payload decryption error occurs.
type payloadErrorAction int

const (
	payloadActionReturnError      payloadErrorAction = iota
	payloadActionRetry                               // Retry (BoxIDNotFound on read)
	payloadActionIdempotentSuccess                   // Treat as success (BoxAlreadyExists on write)
)

// determinePayloadErrorAction decides what to do with a decryption error
// based on the error type and the ARQ message flags.
func determinePayloadErrorAction(err error, isRead bool, noRetryOnBoxIDNotFound bool, noIdempotentBoxAlreadyExists bool) payloadErrorAction {
	var re *replicaError
	if !errors.As(err, &re) {
		return payloadActionReturnError
	}

	// BoxIDNotFound on read: retry unless NoRetryOnBoxIDNotFound is set
	if re.code == pigeonhole.ReplicaErrorBoxIDNotFound && isRead && !noRetryOnBoxIDNotFound {
		return payloadActionRetry
	}

	// BoxAlreadyExists on write: idempotent success unless NoIdempotentBoxAlreadyExists is set
	if re.code == pigeonhole.ReplicaErrorBoxAlreadyExists && !isRead && !noIdempotentBoxAlreadyExists {
		return payloadActionIdempotentSuccess
	}

	return payloadActionReturnError
}

// mapDecryptionErrorToCode maps a decryption error to a thin client error code.
func mapDecryptionErrorToCode(err error) uint8 {
	switch {
	case errors.Is(err, errMKEMDecryptionFailed):
		return thin.ThinClientErrorMKEMDecryptionFailed
	case errors.Is(err, errBACAPDecryptionFailed):
		return thin.ThinClientErrorBACAPDecryptionFailed
	default:
		var re *replicaError
		if errors.As(err, &re) {
			return re.code
		}
		return thin.ThinClientErrorInternalError
	}
}

// handlePayloadReply processes a payload reply and sends it to the thin client.
func (d *Daemon) handlePayloadReply(arqMessage *ARQMessage, courierEnvelopeReply *pigeonhole.CourierEnvelopeReply, conn *incomingConn) {
	plaintext, err := d.decryptPigeonholeReply(arqMessage, courierEnvelopeReply)
	if err != nil {
		d.log.Errorf("handlePayloadReply: failed to decrypt reply: %s", err)

		action := determinePayloadErrorAction(err, arqMessage.IsRead, arqMessage.NoRetryOnBoxIDNotFound, arqMessage.NoIdempotentBoxAlreadyExists)

		switch action {
		case payloadActionRetry:
			d.log.Debugf("handlePayloadReply: BoxIDNotFound for read operation, scheduling retry (attempt %d)",
				arqMessage.Retransmissions+1)

			newSurbID := &[sphinxConstants.SURBIDLength]byte{}
			_, err := rand.Reader.Read(newSurbID[:])
			if err != nil {
				d.log.Errorf("handlePayloadReply: failed to generate SURB ID for retry: %s", err)
				break // fall through to error handling
			}

			pkt, surbKey, rtt, err := d.client.ComposeSphinxPacketForQuery(&thin.SendChannelQuery{
				DestinationIdHash: arqMessage.DestinationIdHash,
				RecipientQueueID:  arqMessage.RecipientQueueID,
				Payload:           arqMessage.Payload,
			}, newSurbID)
			if err != nil {
				d.log.Errorf("handlePayloadReply: failed to compose packet for retry: %s", err)
				break // fall through to error handling
			}

			d.replyLock.Lock()
			delete(d.arqSurbIDMap, *arqMessage.SURBID)
			arqMessage.SURBID = newSurbID
			arqMessage.SURBDecryptionKeys = surbKey
			arqMessage.Retransmissions++
			arqMessage.SentAt = time.Now()
			arqMessage.ReplyETA = rtt
			arqMessage.State = ARQStateWaitingForACK
			d.arqSurbIDMap[*newSurbID] = arqMessage
			d.replyLock.Unlock()

			myRtt := arqMessage.SentAt.Add(arqMessage.ReplyETA)
			myRtt = myRtt.Add(RoundTripTimeSlop)
			priority := uint64(myRtt.UnixNano())
			d.arqTimerQueue.Push(priority, newSurbID)

			err = d.client.SendPacket(pkt)
			if err != nil {
				d.log.Errorf("handlePayloadReply: failed to send retry packet: %s", err)
			}
			d.log.Debugf("handlePayloadReply: Sent retry for BoxIDNotFound, attempt %d", arqMessage.Retransmissions)
			return

		case payloadActionIdempotentSuccess:
			d.log.Debugf("handlePayloadReply: BoxAlreadyExists for write operation - treating as idempotent success")
			d.replyLock.Lock()
			delete(d.arqSurbIDMap, *arqMessage.SURBID)
			delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
			d.replyLock.Unlock()

			conn.sendResponse(&Response{
				AppID: arqMessage.AppID,
				StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
					QueryID:             arqMessage.QueryID,
					ErrorCode:           thin.ThinClientSuccess,
					CourierIdentityHash: arqMessage.DestinationIdHash,
					CourierQueueID:      arqMessage.RecipientQueueID,
				},
			})
			return
		}

		// payloadActionReturnError (or retry/idempotent fell through on infrastructure failure)
		d.replyLock.Lock()
		delete(d.arqSurbIDMap, *arqMessage.SURBID)
		delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
		d.replyLock.Unlock()

		errorCode := mapDecryptionErrorToCode(err)
		d.log.Debugf("handlePayloadReply: returning error code %d", errorCode)

		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:             arqMessage.QueryID,
				ErrorCode:           errorCode,
				CourierIdentityHash: arqMessage.DestinationIdHash,
				CourierQueueID:      arqMessage.RecipientQueueID,
			},
		})
		return
	}

	// Remove from ARQ tracking
	d.replyLock.Lock()
	delete(d.arqSurbIDMap, *arqMessage.SURBID)
	delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
	d.replyLock.Unlock()

	// Handle writes: for write operations, we don't expect any payload data.
	// A successful write returns nil plaintext and nil error.
	if !arqMessage.IsRead {
		d.log.Debugf("handlePayloadReply: Write operation completed successfully")
		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:             arqMessage.QueryID,
				ErrorCode:           thin.ThinClientSuccess,
				CourierIdentityHash: arqMessage.DestinationIdHash,
				CourierQueueID:      arqMessage.RecipientQueueID,
			},
		})
		return
	}

	// Defensive fallback: detect tombstones by empty plaintext after BACAP decryption.
	// The primary path is via ReplicaErrorTombstone from the replica, but this catches
	// any case where the tombstone error code was not set.
	if len(plaintext) == 0 {
		d.log.Debugf("handlePayloadReply: Tombstone detected (empty plaintext)")
		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:             arqMessage.QueryID,
				Plaintext:           []byte{},
				ErrorCode:           pigeonhole.ReplicaErrorTombstone,
				CourierIdentityHash: arqMessage.DestinationIdHash,
				CourierQueueID:      arqMessage.RecipientQueueID,
			},
		})
		return
	}

	// Unpad the plaintext (remove length prefix and padding)
	unpaddedPlaintext, err := pigeonhole.ExtractMessageFromPaddedPayload(plaintext)
	if err != nil {
		d.log.Errorf("handlePayloadReply: Failed to unpad plaintext: %v", err)
		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:             arqMessage.QueryID,
				ErrorCode:           thin.ThinClientErrorInternalError,
				CourierIdentityHash: arqMessage.DestinationIdHash,
				CourierQueueID:      arqMessage.RecipientQueueID,
			},
		})
		return
	}

	// Send success with unpadded plaintext to thin client
	conn.sendResponse(&Response{
		AppID: arqMessage.AppID,
		StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
			QueryID:             arqMessage.QueryID,
			Plaintext:           unpaddedPlaintext,
			ErrorCode:           thin.ThinClientSuccess,
			CourierIdentityHash: arqMessage.DestinationIdHash,
			CourierQueueID:      arqMessage.RecipientQueueID,
		},
	})
}

type innerMessageType int

const (
	innerMessageRead  innerMessageType = 0
	innerMessageWrite innerMessageType = 1
)

// classifyReadReplyError determines whether the read reply error code allows
// proceeding with decryption. Success (0) and tombstone (11) proceed;
// all other error codes are returned as replicaError.
func classifyReadReplyError(errorCode uint8) (shouldProceed bool, isTombstone bool, err error) {
	if errorCode == 0 {
		return true, false, nil
	}
	if errorCode == pigeonhole.ReplicaErrorTombstone {
		return true, true, nil
	}
	return false, false, &replicaError{code: errorCode}
}

// classifyInnerMessage validates and classifies a decrypted replica inner message.
func classifyInnerMessage(msg *pigeonhole.ReplicaMessageReplyInnerMessage) (innerMessageType, error) {
	switch msg.MessageType {
	case 0:
		if msg.ReadReply == nil {
			return 0, fmt.Errorf("read reply (type 0) has nil ReadReply")
		}
		return innerMessageRead, nil
	case 1:
		if msg.WriteReply == nil {
			return 0, fmt.Errorf("write reply (type 1) has nil WriteReply")
		}
		return innerMessageWrite, nil
	default:
		return 0, fmt.Errorf("unexpected inner message type: %d", msg.MessageType)
	}
}

// classifyWriteReply processes a write reply, returning nil on success
// or a replicaError on failure.
func classifyWriteReply(reply *pigeonhole.ReplicaWriteReply) ([]byte, error) {
	if reply.ErrorCode != 0 {
		return nil, &replicaError{code: reply.ErrorCode}
	}
	return nil, nil
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

	// Classify and validate the inner message
	msgType, err := classifyInnerMessage(innerMsg)
	if err != nil {
		d.log.Errorf("decryptPigeonholeReply: %v", err)
		return nil, err
	}

	// Handle read reply
	if msgType == innerMessageRead {
		d.log.Debugf("decryptPigeonholeReply: Processing read reply, ErrorCode: %d, Payload length: %d",
			innerMsg.ReadReply.ErrorCode, len(innerMsg.ReadReply.Payload))

		shouldProceed, _, err := classifyReadReplyError(innerMsg.ReadReply.ErrorCode)
		if !shouldProceed {
			return nil, err
		}

		// Perform BACAP decryption if this is a read operation
		if arqMessage.IsRead && arqMessage.ReadCap != nil && arqMessage.MessageBoxIndex != nil {
			// Deserialize the MessageBoxIndex
			messageBoxIndex, err := bacap.NewEmptyMessageBoxIndexFromBytes(arqMessage.MessageBoxIndex)
			if err != nil {
				d.log.Errorf("decryptPigeonholeReply: Failed to deserialize MessageBoxIndex: %v", err)
				return nil, fmt.Errorf("%w: failed to deserialize MessageBoxIndex: %v", errBACAPDecryptionFailed, err)
			}
			d.log.Debugf("decryptPigeonholeReply: Performing BACAP decryption, Idx64=%d", messageBoxIndex.Idx64)

			// Create a StatefulReader from the ReadCap and MessageBoxIndex
			statefulReader, err := bacap.NewStatefulReaderWithIndex(arqMessage.ReadCap, constants.PIGEONHOLE_CTX, messageBoxIndex)
			if err != nil {
				d.log.Errorf("decryptPigeonholeReply: Failed to create StatefulReader: %v", err)
				return nil, fmt.Errorf("%w: failed to create StatefulReader: %v", errBACAPDecryptionFailed, err)
			}

			// Calculate the expected BoxID from the ReadCap and MessageBoxIndex
			expectedBoxID := messageBoxIndex.BoxIDForContext(arqMessage.ReadCap, constants.PIGEONHOLE_CTX)
			d.log.Errorf("decryptPigeonholeReply: BoxID comparison - Expected: %x, Got from replica: %x",
				expectedBoxID.Bytes(), innerMsg.ReadReply.BoxID)

			// Decrypt the BACAP payload (also verifies signature)
			signature := (*[bacap.SignatureSize]byte)(innerMsg.ReadReply.Signature[:])
			plaintext, err := statefulReader.DecryptNext(
				[]byte(constants.PIGEONHOLE_CTX),
				innerMsg.ReadReply.BoxID,
				innerMsg.ReadReply.Payload,
				*signature)
			if err != nil {
				if innerMsg.ReadReply.ErrorCode == pigeonhole.ReplicaErrorTombstone {
					d.log.Errorf("decryptPigeonholeReply: tombstone signature verification failed: %v", err)
					return nil, &replicaError{code: thin.ThinClientErrorInvalidTombstoneSig}
				}
				d.log.Errorf("decryptPigeonholeReply: BACAP decryption failed: %v", err)
				return nil, fmt.Errorf("%w: %v", errBACAPDecryptionFailed, err)
			}

			if innerMsg.ReadReply.ErrorCode == pigeonhole.ReplicaErrorTombstone {
				d.log.Debugf("decryptPigeonholeReply: verified tombstone at Idx64=%d", messageBoxIndex.Idx64)
				return nil, &replicaError{code: pigeonhole.ReplicaErrorTombstone}
			}

			d.log.Debugf("decryptPigeonholeReply: BACAP decryption successful, plaintext length: %d", len(plaintext))
			return plaintext, nil
		}

		// If not a read operation, return the MKEM-decrypted payload as-is
		d.log.Debugf("decryptPigeonholeReply: Returning MKEM-decrypted payload of length %d", len(innerMsg.ReadReply.Payload))
		return innerMsg.ReadReply.Payload, nil
	}

	// Handle write reply
	d.log.Debugf("decryptPigeonholeReply: Processing write reply, ErrorCode: %d", innerMsg.WriteReply.ErrorCode)
	return classifyWriteReply(innerMsg.WriteReply)
}
