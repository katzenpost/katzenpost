// SPDX-FileCopyrightText: (c) 2026  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
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

	// Create the ARQ message
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

	// Send immediate acknowledgment to thin client
	conn.sendResponse(&Response{
		AppID: request.AppID,
		StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
			QueryID:   req.QueryID,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
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
	if ok && surbID != nil {
		delete(d.arqSurbIDMap, *surbID)
		delete(d.arqEnvelopeHashMap, *req.EnvelopeHash)
	}
	d.replyLock.Unlock()

	if !ok {
		d.log.Debugf("cancelResendingEncryptedMessage: EnvelopeHash %x not found", req.EnvelopeHash[:])
		// Still send success - the message may have already completed
	}

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
		// Send error to thin client
		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:   arqMessage.QueryID,
				ErrorCode: courierEnvelopeReply.ErrorCode,
			},
		})
		return
	}

	// For writes (ACK type = 0), just acknowledge success
	if courierEnvelopeReply.ReplyType == pigeonhole.ReplyTypeACK {
		d.log.Debugf("handlePigeonholeARQReply: write ACK received for EnvelopeHash %x", arqMessage.EnvelopeHash[:])
		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:   arqMessage.QueryID,
				ErrorCode: thin.ThinClientSuccess,
			},
		})
		return
	}

	// For reads (payload type = 1), decrypt and return plaintext
	if courierEnvelopeReply.ReplyType == pigeonhole.ReplyTypePayload {
		plaintext, err := d.decryptPigeonholeReply(arqMessage, courierEnvelopeReply)
		if err != nil {
			d.log.Errorf("handlePigeonholeARQReply: failed to decrypt reply: %s", err)
			conn.sendResponse(&Response{
				AppID: arqMessage.AppID,
				StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
					QueryID:   arqMessage.QueryID,
					ErrorCode: thin.ThinClientErrorInternalError,
				},
			})
			return
		}

		conn.sendResponse(&Response{
			AppID: arqMessage.AppID,
			StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
				QueryID:   arqMessage.QueryID,
				Plaintext: plaintext,
				ErrorCode: thin.ThinClientSuccess,
			},
		})
		return
	}

	d.log.Errorf("handlePigeonholeARQReply: unknown reply type %d", courierEnvelopeReply.ReplyType)
}

// decryptPigeonholeReply decrypts the Pigeonhole envelope reply using the stored EnvelopeDescriptor.
func (d *Daemon) decryptPigeonholeReply(arqMessage *ARQMessage, env *pigeonhole.CourierEnvelopeReply) ([]byte, error) {
	// Deserialize the EnvelopeDescriptor
	envelopeDesc, err := EnvelopeDescriptorFromBytes(arqMessage.EnvelopeDescriptor)
	if err != nil {
		return nil, err
	}

	// Reconstruct the NIKE private key
	privateKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPrivateKey(envelopeDesc.EnvelopeKey)
	if err != nil {
		return nil, err
	}

	// Reuse the existing decryptMKEMEnvelope function
	innerMsg, err := d.decryptMKEMEnvelope(env, envelopeDesc, privateKey)
	if err != nil {
		return nil, err
	}

	// Handle read reply
	if innerMsg.MessageType == 0 && innerMsg.ReadReply != nil {
		if innerMsg.ReadReply.ErrorCode != 0 {
			return nil, fmt.Errorf("read reply error code: %d", innerMsg.ReadReply.ErrorCode)
		}
		// Return the decrypted plaintext from the read reply
		return innerMsg.ReadReply.Payload, nil
	}

	return nil, fmt.Errorf("unexpected inner message type: %d", innerMsg.MessageType)
}
