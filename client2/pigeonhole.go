// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
	hpqcRand "github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

var (
	// Package-level cryptographically secure random number generator
	secureRand = hpqcRand.NewMath()
)

const (
	// Error message for missing connection
	errNoConnectionForAppID = "no connection associated with AppID %x"
)

// EnvelopeDescriptor supplies us with everthing we need to decrypt
// an encrypted envelope reply from a storage replica via the courier.
// The assumption is that we have access to the PKI document for the
// Epoch in which the envelope was sent.
type EnvelopeDescriptor struct {
	// Epoch is the Katzenpost epoch in which the ReplyIndex is valid.
	Epoch uint64

	// ReplicaNums are the replica numbers used for this envelope.
	ReplicaNums [2]uint8

	// EnvelopeKeys is tyhe Private NIKE Key used with our MKEM scheme.
	EnvelopeKey []byte
}

// StoredEnvelopeData contains the envelope and associated box ID for reuse
type StoredEnvelopeData struct {
	Envelope *pigeonhole.CourierEnvelope
	BoxID    *[bacap.BoxIDSize]byte
}

// ChannelDescriptor describes a pigeonhole channel and supplies us with
// everthing we need to read or write to the channel.
type ChannelDescriptor struct {
	StatefulWriter     *bacap.StatefulWriter
	StatefulWriterLock sync.Mutex

	StatefulReader     *bacap.StatefulReader
	StatefulReaderLock sync.Mutex

	EnvelopeDescriptors     map[[hash.HashSize]byte]*EnvelopeDescriptor
	EnvelopeDescriptorsLock sync.RWMutex

	StoredEnvelopes     map[[thin.MessageIDLength]byte]*StoredEnvelopeData
	StoredEnvelopesLock sync.RWMutex
}

func GetRandomCourier(doc *cpki.Document) (*[hash.HashSize]byte, []byte) {
	courierServices := common.FindServices(constants.CourierServiceName, doc)
	if len(courierServices) == 0 {
		panic("wtf no courier services")
	}
	courierService := courierServices[secureRand.Intn(len(courierServices))]
	serviceIdHash := hash.Sum256(courierService.MixDescriptor.IdentityKey)
	return &serviceIdHash, courierService.RecipientQueueID
}

func NewPigeonholeChannel() (*bacap.StatefulWriter, *bacap.ReadCap, *bacap.WriteCap) {
	owner, err := bacap.NewWriteCap(rand.Reader)
	if err != nil {
		panic(err)
	}
	statefulWriter, err := bacap.NewStatefulWriter(owner, constants.PIGEONHOLE_CTX)
	if err != nil {
		panic(err)
	}
	bobReadCap := owner.ReadCap()
	return statefulWriter, bobReadCap, owner
}

// createEnvelopeFromMessage creates a CourierEnvelope from a ReplicaInnerMessage
func createEnvelopeFromMessage(msg *pigeonhole.ReplicaInnerMessage, doc *cpki.Document, isRead bool, replyIndex uint8) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {
	intermediateReplicas, replicaPubKeys, err := pigeonhole.GetRandomIntermediateReplicas(doc)
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

	var isReadFlag uint8 = 0
	if isRead {
		isReadFlag = 1
	}

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
		IsRead:               isReadFlag,
	}
	return envelope, mkemPrivateKey, nil
}

func CreateChannelWriteRequest(
	statefulWriter *bacap.StatefulWriter,
	payload []byte,
	doc *cpki.Document,
	geometry *pigeonholeGeo.Geometry) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {

	// Validate that the payload can fit within the geometry's BoxPayloadLength
	// CreatePaddedPayload requires 4 bytes for length prefix plus the payload
	minRequiredSize := len(payload) + 4
	if minRequiredSize > geometry.BoxPayloadLength {
		return nil, nil, fmt.Errorf("payload too large: %d bytes (+ 4 byte length prefix) exceeds BoxPayloadLength of %d bytes",
			len(payload), geometry.BoxPayloadLength)
	}

	// Pad the payload to the geometry's BoxPayloadLength to fill the user forward sphinx payloads
	paddedPayload, err := pigeonhole.CreatePaddedPayload(payload, geometry.BoxPayloadLength)
	if err != nil {
		return nil, nil, err
	}

	boxID, ciphertext, sigraw, err := statefulWriter.EncryptNext(paddedPayload)
	if err != nil {
		return nil, nil, err
	}

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	var boxIDArray [32]uint8
	copy(boxIDArray[:], boxID[:])
	var sigArray [64]uint8
	copy(sigArray[:], sig[:])

	writeRequest := &pigeonhole.ReplicaWrite{
		BoxID:      boxIDArray,
		Signature:  sigArray,
		PayloadLen: uint32(len(ciphertext)),
		Payload:    ciphertext,
	}
	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg:    writeRequest,
	}

	return createEnvelopeFromMessage(msg, doc, false, 0)
}

// CreateChannelWriteRequestPrepareOnly prepares a write request WITHOUT advancing StatefulWriter state.
// This allows for deferred state advancement until courier acknowledgment.
func CreateChannelWriteRequestPrepareOnly(
	statefulWriter *bacap.StatefulWriter,
	payload []byte,
	doc *cpki.Document,
	geometry *pigeonholeGeo.Geometry) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {

	// Validate that the payload can fit within the geometry's BoxPayloadLength
	// CreatePaddedPayload requires 4 bytes for length prefix plus the payload
	minRequiredSize := len(payload) + 4
	if minRequiredSize > geometry.BoxPayloadLength {
		return nil, nil, fmt.Errorf("payload too large: %d bytes (+ 4 byte length prefix) exceeds BoxPayloadLength of %d bytes",
			len(payload), geometry.BoxPayloadLength)
	}

	// Pad the payload to the geometry's BoxPayloadLength to fill the user forward sphinx payloads
	paddedPayload, err := pigeonhole.CreatePaddedPayload(payload, geometry.BoxPayloadLength)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt the message WITHOUT advancing state
	boxID, ciphertext, sigraw, err := statefulWriter.PrepareNext(paddedPayload)
	if err != nil {
		return nil, nil, err
	}

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	writeRequest := &pigeonhole.ReplicaWrite{
		BoxID:      boxID,
		Signature:  sig,
		PayloadLen: uint32(len(ciphertext)),
		Payload:    ciphertext,
	}
	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg:    writeRequest,
	}

	return createEnvelopeFromMessage(msg, doc, false, 0)
}

func CreateChannelReadRequest(channelID [thin.ChannelIDLength]byte,
	statefulReader *bacap.StatefulReader,
	doc *cpki.Document) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {

	boxID, err := statefulReader.NextBoxID()
	if err != nil {
		panic(err)
	}

	return CreateChannelReadRequestWithBoxID(channelID, boxID, doc)
}

func CreateChannelReadRequestWithBoxID(channelID [thin.ChannelIDLength]byte,
	boxID *[bacap.BoxIDSize]byte,
	doc *cpki.Document) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {

	// Convert boxID to array
	var boxIDArray [32]uint8
	copy(boxIDArray[:], boxID[:])

	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg: &pigeonhole.ReplicaRead{
			BoxID: boxIDArray,
		},
	}

	fmt.Printf("BOB MKEM ENCRYPT: Starting encryption with message size %d bytes\n", len(msg.Bytes()))
	envelope, mkemPrivateKey, err := createEnvelopeFromMessage(msg, doc, true, 0)
	if err != nil {
		return nil, nil, err
	}

	// DEBUG: Log Bob's MKEM private key for envelope creation
	mkemPrivateKeyBytes, _ := mkemPrivateKey.MarshalBinary()
	fmt.Printf("BOB CREATES ENVELOPE WITH MKEM KEY: %x\n", mkemPrivateKeyBytes[:16]) // First 16 bytes for brevity
	fmt.Printf("BOB MKEM ENCRYPT SUCCESS: Encrypted to %d bytes\n", len(envelope.Ciphertext))

	return envelope, mkemPrivateKey, nil
}

// sendWriteChannelSuccessResponse sends a successful response for write channel creation
func (d *Daemon) sendWriteChannelSuccessResponse(request *Request, channelID uint16, bobReadCap *bacap.ReadCap, writeCap *bacap.WriteCap, currentMessageIndex *bacap.MessageBoxIndex) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateWriteChannelReply: &thin.CreateWriteChannelReply{
			ChannelID:        channelID,
			ReadCap:          bobReadCap,
			WriteCap:         writeCap,
			NextMessageIndex: currentMessageIndex,
			ErrorCode:        thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) createWriteChannel(request *Request) {
	statefulWriter, err := d.createOrResumeStatefulWriter(request)
	if err != nil {
		d.log.Errorf("createWriteChannel failure: %s", err)
		d.sendCreateWriteChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	channelID := d.generateUniqueChannelID()
	d.newChannelMapLock.Lock()
	d.newChannelMap[channelID] = &ChannelDescriptor{
		StatefulWriter:      statefulWriter,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[thin.MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.newChannelMapLock.Unlock()

	currentMessageIndex := statefulWriter.NextIndex
	bobReadCap := statefulWriter.Wcap.ReadCap()
	d.sendWriteChannelSuccessResponse(request, channelID, bobReadCap, statefulWriter.Wcap, currentMessageIndex)
}

// getStoredEnvelope retrieves a previously stored envelope and its private key
// Returns the envelope, private key, and a boolean indicating if found
func (d *Daemon) getStoredEnvelope(messageID *[thin.MessageIDLength]byte, channelDesc *ChannelDescriptor) (*pigeonhole.CourierEnvelope, nike.PrivateKey, bool) {
	channelDesc.StoredEnvelopesLock.RLock()
	storedData, exists := channelDesc.StoredEnvelopes[*messageID]
	channelDesc.StoredEnvelopesLock.RUnlock()

	if !exists {
		return nil, nil, false
	}

	d.log.Debugf("Reusing stored envelope for message ID %x", messageID[:])
	courierEnvelope := storedData.Envelope

	// Retrieve the envelope private key from the envelope descriptors
	envHash := courierEnvelope.EnvelopeHash()

	// DEBUG: Log envelope hash and map size when retrieving
	channelDesc.EnvelopeDescriptorsLock.RLock()
	mapSize := len(channelDesc.EnvelopeDescriptors)
	envDesc, envExists := channelDesc.EnvelopeDescriptors[*envHash]
	channelDesc.EnvelopeDescriptorsLock.RUnlock()

	fmt.Printf("RETRIEVING ENVELOPE HASH: %x (map size: %d, exists: %t)\n", envHash[:], mapSize, envExists)

	if !envExists {
		d.log.Errorf("envelope descriptor not found for stored envelope")
		return nil, nil, false
	}

	envelopePrivateKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPrivateKey(envDesc.EnvelopeKey)
	if err != nil {
		d.log.Errorf("failed to unmarshal stored envelope private key: %s", err)
		return nil, nil, false
	}

	// DEBUG: Log Bob's retrieved MKEM private key
	fmt.Printf("BOB RETRIEVES STORED MKEM KEY: %x\n", envDesc.EnvelopeKey[:16]) // First 16 bytes for brevity

	return courierEnvelope, envelopePrivateKey, true
}

// storeEnvelopeDescriptor stores the envelope descriptor for new envelopes (not reused ones)
func (d *Daemon) storeEnvelopeDescriptor(courierEnvelope *pigeonhole.CourierEnvelope, envelopePrivateKey nike.PrivateKey, channelDesc *ChannelDescriptor, doc *cpki.Document) error {
	envHash := courierEnvelope.EnvelopeHash()

	// DEBUG: Log envelope hash and map size when storing
	channelDesc.EnvelopeDescriptorsLock.RLock()
	mapSize := len(channelDesc.EnvelopeDescriptors)
	channelDesc.EnvelopeDescriptorsLock.RUnlock()
	fmt.Printf("STORING ENVELOPE HASH: %x (map size: %d)\n", envHash[:], mapSize)

	// DEBUG: Log the raw data being hashed to identify the issue
	fmt.Printf("DEBUG ENVELOPE DATA:\n")
	pubKeyLen := len(courierEnvelope.SenderPubkey)
	if pubKeyLen > 32 {
		pubKeyLen = 32
	}
	cipherLen := len(courierEnvelope.Ciphertext)
	if cipherLen > 32 {
		cipherLen = 32
	}
	fmt.Printf("  SenderPubkey: %x\n", courierEnvelope.SenderPubkey[:pubKeyLen])
	fmt.Printf("  Ciphertext: %x\n", courierEnvelope.Ciphertext[:cipherLen])

	// Only store envelope descriptor for new envelopes (not reused ones)
	channelDesc.EnvelopeDescriptorsLock.RLock()
	_, envDescExists := channelDesc.EnvelopeDescriptors[*envHash]
	channelDesc.EnvelopeDescriptorsLock.RUnlock()

	if !envDescExists {
		replicaPubKeys := make([]nike.PublicKey, 2)
		replicaEpoch, _, _ := replicaCommon.ReplicaNow()
		for i, replicaNum := range courierEnvelope.IntermediateReplicas {
			desc, err := replicaCommon.ReplicaNum(replicaNum, doc)
			if err != nil {
				return fmt.Errorf("failed to get replica descriptor: %s", err)
			}
			replicaPubKeys[i], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(desc.EnvelopeKeys[replicaEpoch])
			if err != nil {
				return fmt.Errorf("failed to unmarshal public key: %s", err)
			}
		}

		envelopeKey, err := envelopePrivateKey.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal envelope private key: %s", err)
		}
		channelDesc.EnvelopeDescriptorsLock.Lock()
		channelDesc.EnvelopeDescriptors[*envHash] = &EnvelopeDescriptor{
			Epoch:       doc.Epoch, // Store normal epoch, convert when needed
			ReplicaNums: courierEnvelope.IntermediateReplicas,
			EnvelopeKey: envelopeKey,
		}
		channelDesc.EnvelopeDescriptorsLock.Unlock()
	}
	return nil
}

func (d *Daemon) createOrResumeStatefulWriter(request *Request) (*bacap.StatefulWriter, error) {
	isResuming := request.CreateWriteChannel.WriteCap != nil
	var statefulWriter *bacap.StatefulWriter
	var err error
	if isResuming {
		if err := d.checkWriteCapabilityDedup(request.CreateWriteChannel.WriteCap); err != nil {
			return nil, err
		}
		if request.CreateWriteChannel.MessageBoxIndex == nil {
			statefulWriter, err = bacap.NewStatefulWriter(request.CreateWriteChannel.WriteCap, constants.PIGEONHOLE_CTX)
			if err != nil {
				return nil, err
			}
		} else {
			statefulWriter, err = bacap.NewStatefulWriterWithIndex(
				request.CreateWriteChannel.WriteCap,
				constants.PIGEONHOLE_CTX,
				request.CreateWriteChannel.MessageBoxIndex)
			if err != nil {
				return nil, err
			}
		}
	} else {
		// Create a new WriteCap for a new channel
		newWriteCap, err := bacap.NewWriteCap(rand.Reader)
		if err != nil {
			return nil, err
		}
		statefulWriter, err = bacap.NewStatefulWriter(newWriteCap, constants.PIGEONHOLE_CTX)
		if err != nil {
			return nil, err
		}
	}

	return statefulWriter, nil
}

// sendErrorResponse sends an error response for various channel operations
func (d *Daemon) sendErrorResponse(request *Request, errorCode uint8, responseType string) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		return
	}

	response := &Response{AppID: request.AppID}

	switch responseType {
	case "CreateWriteChannel":
		response.CreateWriteChannelReply = &thin.CreateWriteChannelReply{
			ChannelID: 0,
			ErrorCode: errorCode,
		}
	case "CreateReadChannel":
		response.CreateReadChannelReply = &thin.CreateReadChannelReply{
			ChannelID: 0,
			ErrorCode: errorCode,
		}
	case "WriteChannel":
		response.WriteChannelReply = &thin.WriteChannelReply{
			ChannelID: request.WriteChannel.ChannelID,
			ErrorCode: errorCode,
		}
	case "ReadChannel":
		response.ReadChannelReply = &thin.ReadChannelReply{
			MessageID: request.ReadChannel.MessageID,
			ChannelID: request.ReadChannel.ChannelID,
			ErrorCode: errorCode,
		}
	}

	conn.sendResponse(response)
}

func (d *Daemon) sendCreateWriteChannelError(request *Request, errorCode uint8) {
	d.sendErrorResponse(request, errorCode, "CreateWriteChannel")
}

func (d *Daemon) sendCreateReadChannelError(request *Request, errorCode uint8) {
	d.sendErrorResponse(request, errorCode, "CreateReadChannel")
}

func (d *Daemon) sendWriteChannelError(request *Request, errorCode uint8) {
	d.sendErrorResponse(request, errorCode, "WriteChannel")
}

func (d *Daemon) sendReadChannelError(request *Request, errorCode uint8) {
	d.sendErrorResponse(request, errorCode, "ReadChannel")
}

func (d *Daemon) createOrResumeStatefulReader(request *Request) (*bacap.StatefulReader, error) {
	if request.CreateReadChannel.ReadCap == nil {
		return nil, errors.New("CreateReadChannel requires a ReadCap")
	}

	var statefulReader *bacap.StatefulReader
	var err error

	if request.CreateReadChannel.MessageBoxIndex == nil {
		statefulReader, err = bacap.NewStatefulReader(request.CreateReadChannel.ReadCap, constants.PIGEONHOLE_CTX)
		if err != nil {
			return nil, err
		}
	} else {
		statefulReader, err = bacap.NewStatefulReaderWithIndex(request.CreateReadChannel.ReadCap, constants.PIGEONHOLE_CTX, request.CreateReadChannel.MessageBoxIndex)
		if err != nil {
			return nil, err
		}
	}
	return statefulReader, nil
}

func (d *Daemon) createReadChannel(request *Request) {
	statefulReader, err := d.createOrResumeStatefulReader(request)
	if err != nil {
		d.log.Errorf("createReadChannel failure: %s", err)
		d.sendCreateReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	channelID := d.generateUniqueChannelID()
	d.newChannelMapLock.Lock()
	d.newChannelMap[channelID] = &ChannelDescriptor{
		StatefulReader:      statefulReader,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[thin.MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.newChannelMapLock.Unlock()

	currentMessageIndex := statefulReader.NextIndex
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("createReadChannel failure: "+errNoConnectionForAppID, request.AppID[:])
		d.sendCreateReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateReadChannelReply: &thin.CreateReadChannelReply{
			ChannelID:        channelID,
			NextMessageIndex: currentMessageIndex,
			ErrorCode:        thin.ThinClientSuccess,
		},
	})
}

// checkWriteCapabilityDedup checks if a WriteCap is already in use and adds it to the dedup map
func (d *Daemon) checkWriteCapabilityDedup(writeCap *bacap.WriteCap) error {
	writeCapBytes, err := writeCap.MarshalBinary()
	if err != nil {
		return err
	}

	capHash := hash.Sum256(writeCapBytes)
	d.capabilityLock.Lock()
	defer d.capabilityLock.Unlock()

	if d.usedWriteCaps[capHash] {
		return errors.New("capability already in use")
	}

	// Mark this capability as used
	d.usedWriteCaps[capHash] = true
	return nil
}

func (d *Daemon) writeChannel(request *Request) {
	channelID := request.WriteChannel.ChannelID

	d.newChannelMapLock.RLock()
	channelDesc, ok := d.newChannelMap[channelID]
	d.newChannelMapLock.RUnlock()
	if !ok {
		d.log.Errorf("writeChannel failure: no channel found for channelID %d", channelID)
		d.sendWriteChannelError(request, thin.ThinClientErrorChannelNotFound)
		return
	}

	// Check if this is a write channel (has StatefulWriter)
	if channelDesc.StatefulWriter == nil {
		d.log.Errorf("writeChannel failure: channel %d is not a write channel", channelID)
		d.sendWriteChannelError(request, thin.ThinClientErrorInvalidChannel)
		return
	}

	_, doc := d.client.CurrentDocument()

	channelDesc.StatefulWriterLock.Lock()
	courierEnvelope, envelopePrivateKey, err := CreateChannelWriteRequestPrepareOnly(
		channelDesc.StatefulWriter,
		request.WriteChannel.Payload,
		doc,
		d.cfg.PigeonholeGeometry)
	if err != nil {
		channelDesc.StatefulWriterLock.Unlock()
		d.log.Errorf("writeChannel failure: failed to create write request: %s", err)
		d.sendWriteChannelError(request, thin.ThinClientErrorInternalError)
		return
	}
	nextMessageIndex, err := channelDesc.StatefulWriter.GetNextMessageIndex()
	if err != nil {
		channelDesc.StatefulWriterLock.Unlock()
		d.log.Errorf("writeChannel failure: failed to get next message index: %s", err)
		d.sendWriteChannelError(request, thin.ThinClientErrorInternalError)
		return
	}
	channelDesc.StatefulWriterLock.Unlock()

	envHash := courierEnvelope.EnvelopeHash()
	channelDesc.EnvelopeDescriptorsLock.Lock()
	channelDesc.EnvelopeDescriptors[*envHash] = &EnvelopeDescriptor{
		Epoch:       doc.Epoch,
		ReplicaNums: courierEnvelope.IntermediateReplicas,
		EnvelopeKey: envelopePrivateKey.Bytes(),
	}
	channelDesc.EnvelopeDescriptorsLock.Unlock()

	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		d.sendWriteChannelError(request, thin.ThinClientErrorConnectionLost)
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		WriteChannelReply: &thin.WriteChannelReply{
			ChannelID:          channelID,
			SendMessagePayload: courierQuery.Bytes(),
			NextMessageIndex:   nextMessageIndex,
			ErrorCode:          thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) readChannel(request *Request) {
	channelID := request.ReadChannel.ChannelID

	d.newChannelMapLock.RLock()
	channelDesc, ok := d.newChannelMap[channelID]
	d.newChannelMapLock.RUnlock()

	if !ok {
		d.log.Errorf("readChannel failure: no channel found for channelID %d", channelID)
		d.sendReadChannelError(request, thin.ThinClientErrorChannelNotFound)
		return
	}

	// Check if this is a read channel (has StatefulReader)
	if channelDesc.StatefulReader == nil {
		d.log.Errorf("readChannel failure: channel %d is not a read channel", channelID)
		d.sendReadChannelError(request, thin.ThinClientErrorInvalidChannel)
		return
	}

	_, doc := d.client.CurrentDocument()

	channelDesc.StatefulReaderLock.Lock()
	boxID, err := channelDesc.StatefulReader.NextBoxID()
	if err != nil {
		channelDesc.StatefulReaderLock.Unlock()
		d.log.Errorf("readChannel failure: failed to get next box ID: %s", err)
		d.sendReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}
	nextMessageIndex, err := channelDesc.StatefulReader.NextIndex.NextIndex()
	channelDesc.StatefulReaderLock.Unlock()

	if err != nil {
		d.log.Errorf("readChannel failure: failed to get next message index: %s", err)
		d.sendReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg: &pigeonhole.ReplicaRead{
			BoxID: *boxID,
		},
	}

	// Use the ReplyIndex from the request, defaulting to 0 if not specified
	replyIndex := uint8(0)
	if request.ReadChannel.ReplyIndex != nil {
		replyIndex = *request.ReadChannel.ReplyIndex
	}

	courierEnvelope, envelopePrivateKey, err := createEnvelopeFromMessage(msg, doc, true, replyIndex)
	if err != nil {
		d.log.Errorf("readChannel failure: failed to create envelope: %s", err)
		d.sendReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	envHash := courierEnvelope.EnvelopeHash()
	channelDesc.EnvelopeDescriptorsLock.Lock()
	channelDesc.EnvelopeDescriptors[*envHash] = &EnvelopeDescriptor{
		Epoch:       doc.Epoch,
		ReplicaNums: courierEnvelope.IntermediateReplicas,
		EnvelopeKey: envelopePrivateKey.Bytes(),
	}
	channelDesc.EnvelopeDescriptorsLock.Unlock()

	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		d.sendReadChannelError(request, thin.ThinClientErrorConnectionLost)
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ReadChannelReply: &thin.ReadChannelReply{
			MessageID:          request.ReadChannel.MessageID,
			ChannelID:          channelID,
			SendMessagePayload: courierQuery.Bytes(),
			NextMessageIndex:   nextMessageIndex,
			ReplyIndex:         request.ReadChannel.ReplyIndex,
			ErrorCode:          thin.ThinClientSuccess,
		},
	})
}

// closeChannel closes a pigeonhole channel and cleans up its resources
func (d *Daemon) closeChannel(request *Request) {
	channelID := request.CloseChannel.ChannelID

	d.newChannelMapLock.Lock()
	_, ok := d.newChannelMap[channelID]
	if ok {
		delete(d.newChannelMap, channelID)
	}
	d.newChannelMapLock.Unlock()

	if !ok {
		d.log.Debugf("closeChannel: channel %d not found (already closed or never existed)", channelID)
		return
	}

	// Clean up any stored SURB ID mappings for this channel
	d.newSurbIDToChannelMapLock.Lock()
	toDelete := make([][sphinxConstants.SURBIDLength]byte, 0)
	for surbID, mappedChannelID := range d.newSurbIDToChannelMap {
		if mappedChannelID == channelID {
			toDelete = append(toDelete, surbID)
		}
	}
	for _, surbID := range toDelete {
		delete(d.newSurbIDToChannelMap, surbID)
	}
	d.newSurbIDToChannelMapLock.Unlock()

	d.log.Infof("closeChannel: successfully closed channel %d", channelID)
}
