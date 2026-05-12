// SPDX-FileCopyrightText: (c) 2026  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
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

// sendError delivers an error Response to the thin client identified by
// appID. Returns silently if the client has already disconnected — there
// is nobody to notify, and the client's ARQ bookkeeping is cleaned up via
// cleanupForAppID.
func (d *Daemon) sendError(appID *[AppIDLength]byte, response *Response) {
	conn := d.listener.getConnection(appID)
	if conn == nil {
		return
	}
	conn.sendResponse(response)
}

func (d *Daemon) sendNewKeypairError(request *Request, errorCode uint8) {
	d.sendError(request.AppID, &Response{
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
	d.sendError(request.AppID, &Response{
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
	d.sendError(request.AppID, &Response{
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

// writeInnerMessage builds a ReplicaInnerMessage for a write or tombstone
// from the outputs of a BACAP signing step. A zero-length ciphertext is
// valid and produces a tombstone; PayloadLen is set from the byte length
// either way.
func writeInnerMessage(boxID [bacap.BoxIDSize]byte, ciphertext []byte, sig [bacap.SignatureSize]byte) *pigeonhole.ReplicaInnerMessage {
	return &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // write
		WriteMsg: &pigeonhole.ReplicaWrite{
			BoxID:      boxID,
			Signature:  sig,
			PayloadLen: uint32(len(ciphertext)),
			Payload:    ciphertext,
		},
	}
}

// buildCourierEnvelope MKEM-encrypts a ReplicaInnerMessage to the two
// intermediate replicas responsible for boxID and wraps the result in a
// CourierEnvelope carrying the supplied replicaEpoch. Shared by every
// caller that produces envelopes from a constructed inner message:
// single-payload chunking, multi-destination chunking, and tombstone
// ranges.
func (d *Daemon) buildCourierEnvelope(doc *cpki.Document, replicaEpoch uint64, boxID *[bacap.BoxIDSize]byte, msg *pigeonhole.ReplicaInnerMessage) (*pigeonhole.CourierEnvelope, error) {
	intermediateReplicas, replicaPubKeys, err := pigeonhole.GetRandomIntermediateReplicas(doc, boxID)
	if err != nil {
		return nil, fmt.Errorf("failed to get intermediate replicas: %w", err)
	}
	paddedMsg, err := pigeonhole.PadInnerMessageForEncryption(msg, d.cfg.PigeonholeGeometry)
	if err != nil {
		return nil, fmt.Errorf("failed to pad inner message: %w", err)
	}
	mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(replicaPubKeys, paddedMsg)
	senderPubkey := mkemPrivateKey.Public().Bytes()
	return &pigeonhole.CourierEnvelope{
		IntermediateReplicas: intermediateReplicas,
		Dek1:                 [mkem.DEKSize]byte(mkemCiphertext.DEKCiphertexts[0]),
		Dek2:                 [mkem.DEKSize]byte(mkemCiphertext.DEKCiphertexts[1]),
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(senderPubkey)),
		SenderPubkey:         senderPubkey,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}, nil
}

// encryptWriteChunk pads a user chunk to the geometry's plaintext size
// and runs it through the StatefulWriter to produce the boxID,
// BACAP-encrypted ciphertext, and signature that feed writeInnerMessage.
// If advance is true the writer's NextIndex is advanced (EncryptNext);
// otherwise the writer is only peeked (PrepareNext) and the caller owns
// index advancement.
func (d *Daemon) encryptWriteChunk(writer *bacap.StatefulWriter, chunk []byte, advance bool) ([bacap.BoxIDSize]byte, []byte, [bacap.SignatureSize]byte, error) {
	var zeroBox [bacap.BoxIDSize]byte
	var zeroSig [bacap.SignatureSize]byte
	paddedPayload, err := pigeonhole.CreatePaddedPayload(chunk, d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength+4)
	if err != nil {
		return zeroBox, nil, zeroSig, fmt.Errorf("failed to pad payload: %w", err)
	}
	var (
		boxID      [bacap.BoxIDSize]byte
		ciphertext []byte
		sigraw     []byte
	)
	if advance {
		boxID, ciphertext, sigraw, err = writer.EncryptNext(paddedPayload)
	} else {
		boxID, ciphertext, sigraw, err = writer.PrepareNext(paddedPayload)
	}
	if err != nil {
		return zeroBox, nil, zeroSig, fmt.Errorf("failed to encrypt next message: %w", err)
	}
	var sig [bacap.SignatureSize]byte
	copy(sig[:], sigraw)
	return boxID, ciphertext, sig, nil
}

func (d *Daemon) createCourierEnvelopesFromPayload(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	req := request.CreateCourierEnvelopesFromPayload
	if err := validateEnvelopePayloadRequest(req.Payload, req.DestWriteCap, req.DestStartIndex, d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength); err != nil {
		d.log.Errorf("createCourierEnvelopesFromPayload: %v", err)
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Error("createCourierEnvelopesFromPayload: no PKI document available")
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
		return
	}
	// Derive the replica epoch from the PKI doc we just used for replica
	// selection: wall-clock-based ReplicaNow() could diverge from
	// doc.Epoch around a mixnet-epoch boundary.
	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(doc.Epoch)

	statefulWriter, err := bacap.NewStatefulWriter(req.DestWriteCap, []byte(constants.PIGEONHOLE_CTX))
	if err != nil {
		d.log.Errorf("createCourierEnvelopesFromPayload: failed to create stateful writer: %v", err)
		d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
		return
	}
	statefulWriter.NextIndex = req.DestStartIndex

	maxPayload := d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength - 4
	chunks := chunkPayload(req.Payload, maxPayload)
	envelopes := make([]*pigeonhole.CourierEnvelope, 0, len(chunks))
	for _, chunk := range chunks {
		boxID, ciphertext, sig, err := d.encryptWriteChunk(statefulWriter, chunk, true)
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}
		envelope, err := d.buildCourierEnvelope(doc, replicaEpoch, &boxID, writeInnerMessage(boxID, ciphertext, sig))
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}
		d.log.Debugf("createCourierEnvelopesFromPayload: BoxID=%x", boxID)
		envelopes = append(envelopes, envelope)
	}

	// Single-call semantics: every call stages one fresh encoder, so
	// flush even the partial trailing element on !isLast. Callers that
	// actually want multi-call buffer continuation use the Payloads
	// variant instead.
	encoder := pigeonhole.NewCopyStreamEncoder(d.cfg.PigeonholeGeometry)
	if !req.IsStart {
		encoder.SuppressStart()
	}
	var elements [][]byte
	for _, envelope := range envelopes {
		newElements, err := encoder.AddEnvelope(envelope)
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayload: failed to encode envelope: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadError(request, thin.ThinClientErrorInternalError)
			return
		}
		elements = append(elements, newElements...)
	}
	var trailing [][]byte
	if req.IsLast {
		trailing = encoder.Flush()
	} else {
		trailing = encoder.FlushWithoutFinal()
	}
	elements = append(elements, trailing...)

	d.log.Debugf("createCourierEnvelopesFromPayload: created %d CourierEnvelopes, encoded into %d elements (isStart=%v, isLast=%v)",
		len(envelopes), len(elements), req.IsStart, req.IsLast)

	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromPayloadReply: &thin.CreateCourierEnvelopesFromPayloadReply{
			QueryID:       req.QueryID,
			Envelopes:     elements,
			NextDestIndex: statefulWriter.NextIndex,
			ErrorCode:     thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendCreateCourierEnvelopesFromPayloadError(request *Request, errorCode uint8) {
	d.sendError(request.AppID, &Response{
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

	// Derive the replica epoch from the PKI doc, matching the keys
	// the client selected for this batch. See the note in
	// createCourierEnvelopesFromPayload.
	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(doc.Epoch)

	// Create a fresh encoder and restore buffer from previous call if provided
	encoder := pigeonhole.NewCopyStreamEncoder(d.cfg.PigeonholeGeometry)
	if len(request.CreateCourierEnvelopesFromPayloads.Buffer) > 0 {
		encoder.SetBuffer(&pigeonhole.CopyStreamEncoderState{
			Buffer: request.CreateCourierEnvelopesFromPayloads.Buffer,
		})
	}

	isStart := request.CreateCourierEnvelopesFromPayloads.IsStart
	if !isStart {
		encoder.SuppressStart()
	}

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
		statefulWriter, err := bacap.NewStatefulWriter(dest.WriteCap, []byte(constants.PIGEONHOLE_CTX))
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromPayloads: failed to create stateful writer: %v", err)
			d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
			return
		}

		// Chunk the payload and create CourierEnvelopes for this destination
		for offset := 0; offset < len(dest.Payload); offset += maxPayload {
			end := offset + maxPayload
			if end > len(dest.Payload) {
				end = len(dest.Payload)
			}
			chunk := dest.Payload[offset:end]

			// Reposition the writer to the current index before each
			// chunk; encryptWriteChunk with advance=false peeks without
			// mutating NextIndex so the caller owns advancement.
			statefulWriter.NextIndex = currentIndex
			boxID, ciphertext, sig, err := d.encryptWriteChunk(statefulWriter, chunk, false)
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
				return
			}
			d.log.Debugf("createCourierEnvelopesFromPayloads: dest=%d, Idx64=%d, BoxID=%x", destIdx, currentIndex.Idx64, boxID)

			envelope, err := d.buildCourierEnvelope(doc, replicaEpoch, &boxID, writeInnerMessage(boxID, ciphertext, sig))
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
				return
			}
			newElements, err := encoder.AddEnvelope(envelope)
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: failed to encode envelope: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
				return
			}
			elements = append(elements, newElements...)
			totalEnvelopes++

			currentIndex, err = currentIndex.NextIndex()
			if err != nil {
				d.log.Errorf("createCourierEnvelopesFromPayloads: failed to advance index: %v", err)
				d.sendCreateCourierEnvelopesFromPayloadsError(request, thin.ThinClientErrorInternalError)
				return
			}
		}
		nextDestIndices[destIdx] = currentIndex
	}

	// Flush or return residual buffer
	isLast := request.CreateCourierEnvelopesFromPayloads.IsLast
	var bufferBytes []byte
	if isLast {
		finalElements := encoder.Flush()
		if finalElements != nil {
			elements = append(elements, finalElements...)
		}
	} else {
		// Return residual buffer to caller
		state := encoder.GetBuffer()
		if state != nil {
			bufferBytes = state.Buffer
		}
	}

	d.log.Debugf("createCourierEnvelopesFromPayloads: created %d CourierEnvelopes from %d destinations, encoded into %d elements (isStart=%v, isLast=%v, bufferLen=%d)",
		totalEnvelopes, len(destinations), len(elements), isStart, isLast, len(bufferBytes))

	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromPayloadsReply: &thin.CreateCourierEnvelopesFromPayloadsReply{
			QueryID:         request.CreateCourierEnvelopesFromPayloads.QueryID,
			Envelopes:       elements,
			Buffer:          bufferBytes,
			NextDestIndices: nextDestIndices,
			ErrorCode:       thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendCreateCourierEnvelopesFromPayloadsError(request *Request, errorCode uint8) {
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromPayloadsReply: &thin.CreateCourierEnvelopesFromPayloadsReply{
			QueryID:   request.CreateCourierEnvelopesFromPayloads.QueryID,
			ErrorCode: errorCode,
		},
	})
}

func (d *Daemon) createCourierEnvelopesFromTombstoneRange(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	destWriteCap := request.CreateCourierEnvelopesFromTombstoneRange.DestWriteCap
	destStartIndex := request.CreateCourierEnvelopesFromTombstoneRange.DestStartIndex
	maxCount := request.CreateCourierEnvelopesFromTombstoneRange.MaxCount

	if destWriteCap == nil {
		d.log.Error("createCourierEnvelopesFromTombstoneRange: DestWriteCap is nil")
		d.sendCreateCourierEnvelopesFromTombstoneRangeError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	if destStartIndex == nil {
		d.log.Error("createCourierEnvelopesFromTombstoneRange: DestStartIndex is nil")
		d.sendCreateCourierEnvelopesFromTombstoneRangeError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	if maxCount == 0 {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			CreateCourierEnvelopesFromTombstoneRangeReply: &thin.CreateCourierEnvelopesFromTombstoneRangeReply{
				QueryID:       request.CreateCourierEnvelopesFromTombstoneRange.QueryID,
				NextDestIndex: destStartIndex,
				ErrorCode:     thin.ThinClientSuccess,
			},
		})
		return
	}

	if d.cfg.PigeonholeGeometry == nil {
		d.log.Error("createCourierEnvelopesFromTombstoneRange: PigeonholeGeometry is nil")
		d.sendCreateCourierEnvelopesFromTombstoneRangeError(request, thin.ThinClientErrorInternalError)
		return
	}

	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Error("createCourierEnvelopesFromTombstoneRange: no PKI document available")
		d.sendCreateCourierEnvelopesFromTombstoneRangeError(request, thin.ThinClientErrorInternalError)
		return
	}

	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(doc.Epoch)
	cur := destStartIndex
	var courierEnvelopes []*pigeonhole.CourierEnvelope

	for i := uint32(0); i < maxCount; i++ {
		// Tombstone: sign empty payload with blinded private key, then
		// encrypt the ReplicaWrite via the shared buildCourierEnvelope.
		boxID, sigraw := cur.SignBox(destWriteCap, constants.PIGEONHOLE_CTX, []byte{})
		sig := [bacap.SignatureSize]byte{}
		copy(sig[:], sigraw)

		envelope, err := d.buildCourierEnvelope(doc, replicaEpoch, &boxID, writeInnerMessage(boxID, nil, sig))
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromTombstoneRange: %v", err)
			d.sendCreateCourierEnvelopesFromTombstoneRangeError(request, thin.ThinClientErrorInternalError)
			return
		}
		courierEnvelopes = append(courierEnvelopes, envelope)

		nextIndex, err := cur.NextIndex()
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromTombstoneRange: failed to advance index: %v", err)
			d.sendCreateCourierEnvelopesFromTombstoneRangeError(request, thin.ThinClientErrorInternalError)
			return
		}
		cur = nextIndex
	}

	// Encode via CopyStreamEncoder with stateless buffer continuation
	isStart := request.CreateCourierEnvelopesFromTombstoneRange.IsStart
	isLast := request.CreateCourierEnvelopesFromTombstoneRange.IsLast
	encoder := pigeonhole.NewCopyStreamEncoder(d.cfg.PigeonholeGeometry)

	// Restore buffer from previous call if provided
	if len(request.CreateCourierEnvelopesFromTombstoneRange.Buffer) > 0 {
		encoder.SetBuffer(&pigeonhole.CopyStreamEncoderState{
			Buffer: request.CreateCourierEnvelopesFromTombstoneRange.Buffer,
		})
	}

	if !isStart {
		encoder.SuppressStart()
	}

	var elements [][]byte
	for _, envelope := range courierEnvelopes {
		newElements, err := encoder.AddEnvelope(envelope)
		if err != nil {
			d.log.Errorf("createCourierEnvelopesFromTombstoneRange: failed to encode envelope: %v", err)
			d.sendCreateCourierEnvelopesFromTombstoneRangeError(request, thin.ThinClientErrorInternalError)
			return
		}
		elements = append(elements, newElements...)
	}

	var bufferState []byte
	if isLast {
		finalElements := encoder.Flush()
		if finalElements != nil {
			elements = append(elements, finalElements...)
		}
	} else {
		// Extract only complete elements, return residual buffer to caller
		state := encoder.GetBuffer()
		if state != nil {
			bufferState = state.Buffer
		}
	}

	d.log.Debugf("createCourierEnvelopesFromTombstoneRange: created %d tombstone envelopes, encoded into %d elements (isStart=%v, isLast=%v, bufferLen=%d)",
		len(courierEnvelopes), len(elements), isStart, isLast, len(bufferState))

	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromTombstoneRangeReply: &thin.CreateCourierEnvelopesFromTombstoneRangeReply{
			QueryID:       request.CreateCourierEnvelopesFromTombstoneRange.QueryID,
			Envelopes:     elements,
			Buffer:        bufferState,
			NextDestIndex: cur,
			ErrorCode:     thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendCreateCourierEnvelopesFromTombstoneRangeError(request *Request, errorCode uint8) {
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		CreateCourierEnvelopesFromTombstoneRangeReply: &thin.CreateCourierEnvelopesFromTombstoneRangeReply{
			QueryID:   request.CreateCourierEnvelopesFromTombstoneRange.QueryID,
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
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		NextMessageBoxIndexReply: &thin.NextMessageBoxIndexReply{
			QueryID:   request.NextMessageBoxIndex.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// getMessageBoxIndexCounter returns the BACAP Idx64 counter embedded in a
// MessageBoxIndex. Thin clients that store indexes as opaque blobs use
// this to order and compare them without having to know the binary layout.
func (d *Daemon) getMessageBoxIndexCounter(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	messageBoxIndex := request.GetMessageBoxIndexCounter.MessageBoxIndex
	if messageBoxIndex == nil {
		d.log.Error("getMessageBoxIndexCounter: MessageBoxIndex is nil")
		d.sendGetMessageBoxIndexCounterError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		GetMessageBoxIndexCounterReply: &thin.GetMessageBoxIndexCounterReply{
			QueryID:   request.GetMessageBoxIndexCounter.QueryID,
			Counter:   messageBoxIndex.Idx64,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendGetMessageBoxIndexCounterError(request *Request, errorCode uint8) {
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		GetMessageBoxIndexCounterReply: &thin.GetMessageBoxIndexCounterReply{
			QueryID:   request.GetMessageBoxIndexCounter.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// getPKIDocument returns the cert.Certificate-wrapped signed PKI
// document for the requested epoch, with directory authority
// signatures intact. An epoch of zero is taken to mean the current
// epoch.
func (d *Daemon) getPKIDocument(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	var raw []byte
	epoch := request.GetPKIDocument.Epoch
	if epoch == 0 {
		raw, epoch = d.client.CurrentRawSignedDocument()
	} else {
		raw = d.client.RawSignedDocumentByEpoch(epoch)
	}

	if raw == nil {
		d.sendGetPKIDocumentError(request, epoch, thin.ThinClientErrorServiceUnavailable)
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		GetPKIDocumentReply: &thin.GetPKIDocumentReply{
			QueryID:   request.GetPKIDocument.QueryID,
			Payload:   raw,
			Epoch:     epoch,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) sendGetPKIDocumentError(request *Request, epoch uint64, errorCode uint8) {
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		GetPKIDocumentReply: &thin.GetPKIDocumentReply{
			QueryID:   request.GetPKIDocument.QueryID,
			Epoch:     epoch,
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

// arqSend mints a SURB ID, composes the Sphinx packet for the ARQMessage's
// payload, populates the message's SURB fields, stores it in the ARQ maps
// keyed by envHashKey, schedules the retry timer, and sends the packet.
// The caller must pre-populate AppID, QueryID, EnvelopeHash,
// DestinationIdHash, RecipientQueueID, Payload, State, MessageType (if
// non-default), and any query-specific fields. SURBID, SURBDecryptionKeys,
// SentAt, ReplyETA, and Retransmissions are overwritten here.
//
// An error return indicates that nothing was stored or scheduled; the
// caller should respond with an InternalError code. A SendPacket failure
// after the ARQ is stored is logged but not returned: the ARQ timer will
// retransmit on its next fire.
func (d *Daemon) arqSend(message *ARQMessage, envHashKey [32]byte) error {
	surbID := &[sphinxConstants.SURBIDLength]byte{}
	if _, err := rand.Reader.Read(surbID[:]); err != nil {
		return fmt.Errorf("failed to generate SURB ID: %w", err)
	}

	pkt, surbKey, rtt, err := d.client.ComposeSphinxPacketForQuery(&thin.SendChannelQuery{
		DestinationIdHash: message.DestinationIdHash,
		RecipientQueueID:  message.RecipientQueueID,
		Payload:           message.Payload,
	}, surbID)
	if err != nil {
		return fmt.Errorf("failed to compose packet: %w", err)
	}

	message.SURBID = surbID
	message.SURBDecryptionKeys = surbKey
	message.SentAt = time.Now()
	message.ReplyETA = rtt
	message.Retransmissions = 0

	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = message
	d.arqEnvelopeHashMap[envHashKey] = surbID
	d.replyLock.Unlock()

	priority := uint64(message.SentAt.Add(rtt).Add(RoundTripTimeSlop).UnixNano())
	d.arqTimerQueue.Push(priority, surbID)

	if err := d.client.SendPacket(pkt); err != nil {
		d.log.Warningf("arqSend: initial SendPacket failed, ARQ timer will retry: %s", err)
	}
	return nil
}

// logBoxIDForRequest derives the box ID from the request's ReadCap/WriteCap
// and MessageBoxIndex and emits a debug line. Pure diagnostic; never fails.
func (d *Daemon) logBoxIDForRequest(req *thin.StartResendingEncryptedMessage, isRead bool) {
	boxIDHex := "<unknown>"
	idx64Str := "<unknown>"
	if len(req.MessageBoxIndex) > 0 {
		if mbi, err := bacap.NewEmptyMessageBoxIndexFromBytes(req.MessageBoxIndex); err == nil {
			idx64Str = fmt.Sprintf("%d", mbi.Idx64)
			switch {
			case isRead && req.ReadCap != nil:
				boxIDHex = fmt.Sprintf("%x", req.ReadCap.DeriveBoxID(mbi).Bytes())
			case !isRead && req.WriteCap != nil:
				boxIDHex = fmt.Sprintf("%x", req.WriteCap.DeriveBoxID(mbi).Bytes())
			}
		}
	}
	d.log.Debugf("startResendingEncryptedMessage: isRead=%v, Idx64=%s, boxID=%s, NoRetryOnBoxIDNotFound=%v, NoIdempotentBoxAlreadyExists=%v, EnvelopeHash=%x",
		isRead, idx64Str, boxIDHex, req.NoRetryOnBoxIDNotFound, req.NoIdempotentBoxAlreadyExists, req.EnvelopeHash[:])
}

func (d *Daemon) startResendingEncryptedMessage(request *Request) {
	req := request.StartResendingEncryptedMessage
	if err := validateStartResendingRequest(req); err != nil {
		d.log.Errorf("startResendingEncryptedMessage: %v", err)
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	isRead := req.ReadCap != nil
	d.logBoxIDForRequest(req, isRead)

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

	message := &ARQMessage{
		AppID:                        request.AppID,
		QueryID:                      req.QueryID,
		EnvelopeHash:                 req.EnvelopeHash,
		DestinationIdHash:            destIdHash,
		RecipientQueueID:             recipientQueueID,
		Payload:                      req.MessageCiphertext,
		EnvelopeDescriptor:           req.EnvelopeDescriptor,
		IsRead:                       isRead,
		State:                        ARQStateWaitingForACK,
		ReadCap:                      req.ReadCap,
		MessageBoxIndex:              req.MessageBoxIndex,
		NoRetryOnBoxIDNotFound:       req.NoRetryOnBoxIDNotFound,
		NoIdempotentBoxAlreadyExists: req.NoIdempotentBoxAlreadyExists,
	}

	if err := d.arqSend(message, *req.EnvelopeHash); err != nil {
		d.log.Errorf("startResendingEncryptedMessage: %s", err)
		d.sendStartResendingEncryptedMessageError(request, thin.ThinClientErrorInternalError)
	}
}

func (d *Daemon) sendStartResendingEncryptedMessageError(request *Request, errorCode uint8) {
	d.sendError(request.AppID, &Response{
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

	// Cancel the pending retry so it does not fire and hit a
	// missing-arqSurbIDMap log later.
	if arqMessage != nil && arqMessage.SURBID != nil && d.arqTimerQueue != nil {
		d.arqTimerQueue.Cancel(arqMessage.SURBID)
	}

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
	d.sendError(request.AppID, &Response{
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
		d.dropARQMessage(arqMessage)
		return
	}

	// Parse the CourierQueryReply
	courierQueryReply, err := pigeonhole.ParseCourierQueryReply(surbPayload)
	if err != nil {
		d.log.Errorf("handlePigeonholeARQReply: failed to parse CourierQueryReply: %s", err)
		d.dropARQMessage(arqMessage)
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
		d.dropARQMessage(arqMessage)
		return
	}

	// Handle envelope reply (type 0)
	if courierQueryReply.ReplyType != 0 || courierQueryReply.EnvelopeReply == nil {
		d.log.Errorf("handlePigeonholeARQReply: unexpected reply type %d for envelope operation", courierQueryReply.ReplyType)
		d.dropARQMessage(arqMessage)
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
		if arqMessage.SURBID != nil {
			delete(d.arqSurbIDMap, *arqMessage.SURBID)
		}
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
			d.log.Errorf("handlePigeonholeARQReply: failed to compose packet, rescheduling: %s", err)
			d.rescheduleARQAfterComposeFailure(arqMessage)
			return
		}

		oldSurbID := arqMessage.SURBID

		d.replyLock.Lock()
		// Abort if a concurrent cancel has already cleared this
		// arqMessage. Rotating here would silently un-cancel the
		// operation.
		if oldSurbID == nil {
			d.replyLock.Unlock()
			d.log.Debugf("handlePigeonholeARQReply: arqMessage has nil SURBID, aborting rotation")
			return
		}
		if existing, ok := d.arqSurbIDMap[*oldSurbID]; !ok || existing != arqMessage {
			d.replyLock.Unlock()
			d.log.Debugf("handlePigeonholeARQReply: arqMessage no longer tracked (cancelled), aborting rotation for EnvelopeHash %x", arqMessage.EnvelopeHash[:])
			return
		}
		if d.listener.getConnection(arqMessage.AppID) == nil {
			d.replyLock.Unlock()
			d.log.Debugf("handlePigeonholeARQReply: connection gone for AppID %x, dropping ARQ for EnvelopeHash %x", arqMessage.AppID[:], arqMessage.EnvelopeHash[:])
			return
		}
		d.rotateARQSurbIDLocked(arqMessage, newSurbID, surbKey, rtt)
		d.replyLock.Unlock()

		if oldSurbID != nil {
			d.arqTimerQueue.Cancel(oldSurbID)
		}

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

// CopyPollInterval is the delay between courier polls while a Copy
// command is still InProgress. Small enough that a small Copy finishes
// a round-trip or two early, large enough that a long Copy doesn't
// hammer the courier.
const CopyPollInterval = 5 * time.Second

// handleCopyCommandARQReply handles replies to copy command ARQ
// messages.
//
// The Copy command protocol is async: the courier ACKs receipt with
// Status=InProgress, processes in the background, and delivers the
// terminal Status=Succeeded or Status=Failed on a subsequent poll.
// The daemon polls by re-sending the same Copy command (same WriteCap)
// with a fresh SURB every CopyPollInterval.
//
// Terminal statuses are surfaced to the thin client. InProgress keeps
// the ARQMessage registered (so Cancel still works) and schedules the
// next poll.
func (d *Daemon) handleCopyCommandARQReply(arqMessage *ARQMessage, courierQueryReply *pigeonhole.CourierQueryReply, conn *incomingConn) {
	// Verify this is a copy command reply (ReplyType: 1)
	if courierQueryReply.ReplyType != 1 || courierQueryReply.CopyCommandReply == nil {
		d.log.Errorf("handleCopyCommandARQReply: expected copy command reply (type 1), got type %d",
			courierQueryReply.ReplyType)
		return
	}

	copyCommandReply := courierQueryReply.CopyCommandReply

	d.log.Debugf("handleCopyCommandARQReply: Received copy command reply, Status=%d, ErrorCode=%d, FailedEnvelopeIndex=%d, WriteCapHash=%x",
		copyCommandReply.Status, copyCommandReply.ErrorCode, copyCommandReply.FailedEnvelopeIndex, arqMessage.EnvelopeHash[:])

	switch copyCommandReply.Status {
	case pigeonhole.CopyStatusInProgress:
		// Keep the ARQ state alive and schedule the next poll. We do
		// not notify the thin client yet — it is blocked waiting for a
		// terminal reply via StartResendingCopyCommand.
		d.scheduleCopyCommandPoll(arqMessage)
		return

	case pigeonhole.CopyStatusSucceeded:
		d.replyLock.Lock()
		delete(d.arqSurbIDMap, *arqMessage.SURBID)
		delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
		d.replyLock.Unlock()
		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingCopyCommandReply: &thin.StartResendingCopyCommandReply{
				QueryID:   arqMessage.QueryID,
				ErrorCode: thin.ThinClientSuccess,
			},
		})

	case pigeonhole.CopyStatusFailed:
		d.replyLock.Lock()
		delete(d.arqSurbIDMap, *arqMessage.SURBID)
		delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
		d.replyLock.Unlock()
		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingCopyCommandReply: &thin.StartResendingCopyCommandReply{
				QueryID:             arqMessage.QueryID,
				ErrorCode:           thin.ThinClientErrorCopyCommandFailed,
				ReplicaErrorCode:    copyCommandReply.ErrorCode,
				FailedEnvelopeIndex: copyCommandReply.FailedEnvelopeIndex,
			},
		})

	default:
		d.log.Warningf("handleCopyCommandARQReply: unexpected Status=%d, treating as failure", copyCommandReply.Status)
		d.replyLock.Lock()
		delete(d.arqSurbIDMap, *arqMessage.SURBID)
		delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
		d.replyLock.Unlock()
		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingCopyCommandReply: &thin.StartResendingCopyCommandReply{
				QueryID:   arqMessage.QueryID,
				ErrorCode: thin.ThinClientErrorInternalError,
			},
		})
	}
}

// scheduleCopyCommandPoll keeps the ARQMessage reachable under a fresh
// placeholder SURBID and pushes a timer entry CopyPollInterval out.
// When the timer fires, arqDoResend looks up the placeholder, rotates
// it to a real SURBID, composes a fresh Sphinx packet, and sends —
// which produces the next Copy poll to the courier.
//
// handleReply cleans both ARQ maps when a reply arrives, so without
// this re-registration the thin client's CancelResendingCopyCommand
// would silently no-op during the polling window.
func (d *Daemon) scheduleCopyCommandPoll(arqMessage *ARQMessage) {
	placeholder := &[sphinxConstants.SURBIDLength]byte{}
	if _, err := rand.Reader.Read(placeholder[:]); err != nil {
		d.log.Errorf("scheduleCopyCommandPoll: failed to generate placeholder SURBID: %v", err)
		return
	}

	d.replyLock.Lock()
	// Abort if a concurrent cancel has already removed the arqMessage
	// from the maps. Re-registering here would silently un-cancel the
	// operation.
	oldSurbID := arqMessage.SURBID
	if oldSurbID == nil {
		d.replyLock.Unlock()
		d.log.Debugf("scheduleCopyCommandPoll: arqMessage has nil SURBID, aborting")
		return
	}
	if existing, ok := d.arqSurbIDMap[*oldSurbID]; !ok || existing != arqMessage {
		d.replyLock.Unlock()
		d.log.Debugf("scheduleCopyCommandPoll: arqMessage no longer tracked (cancelled), aborting")
		return
	}
	delete(d.arqSurbIDMap, *oldSurbID)
	arqMessage.SURBID = placeholder
	d.arqSurbIDMap[*placeholder] = arqMessage
	if arqMessage.EnvelopeHash != nil {
		d.arqEnvelopeHashMap[*arqMessage.EnvelopeHash] = placeholder
	}
	d.replyLock.Unlock()

	if d.arqTimerQueue == nil {
		d.log.Debugf("scheduleCopyCommandPoll: arqTimerQueue is nil, skipping poll schedule")
		return
	}
	priority := uint64(time.Now().Add(CopyPollInterval).UnixNano())
	d.arqTimerQueue.Push(priority, placeholder)
	d.log.Debugf("scheduleCopyCommandPoll: next Copy poll scheduled in %v for WriteCapHash %x", CopyPollInterval, arqMessage.EnvelopeHash[:])
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

// resolveCourier picks a courier for a copy-command send: the one the
// client specified if provided, else a random one from the current PKI
// document. A nil PKI document or a lookup failure produces an error
// that the caller should surface as InternalError.
func (d *Daemon) resolveCourier(specifiedHash *[32]byte, specifiedQueueID []byte) (*[32]byte, []byte, error) {
	if specifiedHash != nil && len(specifiedQueueID) > 0 {
		d.log.Debugf("resolveCourier: using specified courier %x", specifiedHash[:8])
		return specifiedHash, specifiedQueueID, nil
	}
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		return nil, nil, fmt.Errorf("no PKI document available")
	}
	return GetRandomCourier(doc)
}

// startResendingCopyCommand starts resending a copy command via the ARQ
// mechanism. It retries forever until cancelled or successful.
func (d *Daemon) startResendingCopyCommand(request *Request) {
	req := request.StartResendingCopyCommand
	if err := validateStartResendingCopyCommandRequest(req); err != nil {
		d.log.Errorf("startResendingCopyCommand: %v", err)
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	writeCapBytes, err := req.WriteCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("startResendingCopyCommand: failed to serialize WriteCap: %s", err)
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInternalError)
		return
	}
	payload, err := (&pigeonhole.CourierQuery{
		QueryType: 1, // CopyCommand
		CopyCommand: &pigeonhole.CopyCommand{
			WriteCapLen: uint32(len(writeCapBytes)),
			WriteCap:    writeCapBytes,
		},
	}).MarshalBinary()
	if err != nil {
		d.log.Errorf("startResendingCopyCommand: failed to serialize CourierQuery: %s", err)
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInternalError)
		return
	}
	writeCapHash := hash.Sum256(writeCapBytes)

	destIdHash, recipientQueueID, err := d.resolveCourier(req.CourierIdentityHash, req.CourierQueueID)
	if err != nil {
		d.log.Errorf("startResendingCopyCommand: %s", err)
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInternalError)
		return
	}

	message := &ARQMessage{
		MessageType:       ARQMessageTypeCopyCommand,
		AppID:             request.AppID,
		QueryID:           req.QueryID,
		EnvelopeHash:      &writeCapHash, // Use WriteCap hash as envelope hash for dedup
		DestinationIdHash: destIdHash,
		RecipientQueueID:  recipientQueueID,
		Payload:           payload,
		State:             ARQStateWaitingForACK, // Only one state for copy commands
	}

	if err := d.arqSend(message, writeCapHash); err != nil {
		d.log.Errorf("startResendingCopyCommand: %s", err)
		d.sendStartResendingCopyCommandError(request, thin.ThinClientErrorInternalError)
		return
	}
	d.log.Debugf("startResendingCopyCommand: Sending copy command, QueryID=%x, WriteCapHash=%x",
		req.QueryID[:], writeCapHash[:])
}

func (d *Daemon) sendStartResendingCopyCommandError(request *Request, errorCode uint8) {
	d.sendError(request.AppID, &Response{
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

	if arqMessage != nil && arqMessage.SURBID != nil && d.arqTimerQueue != nil {
		d.arqTimerQueue.Cancel(arqMessage.SURBID)
	}

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
	d.sendError(request.AppID, &Response{
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
				d.log.Errorf("handlePayloadReply: failed to compose packet for retry, rescheduling: %s", err)
				d.rescheduleARQAfterComposeFailure(arqMessage)
				return
			}

			oldSurbID := arqMessage.SURBID

			d.replyLock.Lock()
			// Abort if a concurrent cancel has already cleared this
			// arqMessage.
			if oldSurbID == nil {
				d.replyLock.Unlock()
				d.log.Debugf("handlePayloadReply: arqMessage has nil SURBID, aborting retry")
				return
			}
			if existing, ok := d.arqSurbIDMap[*oldSurbID]; !ok || existing != arqMessage {
				d.replyLock.Unlock()
				d.log.Debugf("handlePayloadReply: arqMessage no longer tracked (cancelled), aborting retry for EnvelopeHash %x", arqMessage.EnvelopeHash[:])
				return
			}
			d.rotateARQSurbIDLocked(arqMessage, newSurbID, surbKey, rtt)
			arqMessage.State = ARQStateWaitingForACK
			d.replyLock.Unlock()

			if oldSurbID != nil {
				d.arqTimerQueue.Cancel(oldSurbID)
			}

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
