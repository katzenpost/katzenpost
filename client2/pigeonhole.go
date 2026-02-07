// SPDX-FileCopyrightText: (c) 2026  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/bacap"
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
		ReplicaEpoch:       req.ReplicaEpoch,
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

	// Handle envelope reply (type 0)
	if courierQueryReply.ReplyType != 0 || courierQueryReply.EnvelopeReply == nil {
		d.log.Errorf("handlePigeonholeARQReply: unexpected reply type %d", courierQueryReply.ReplyType)
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

	// Send success with plaintext to thin client
	conn.sendResponse(&Response{
		AppID: arqMessage.AppID,
		StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
			QueryID:   arqMessage.QueryID,
			Plaintext: plaintext,
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
