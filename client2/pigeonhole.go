// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
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

	// EnvelopeKey is the Private NIKE Key used with our MKEM scheme.
	EnvelopeKey []byte
}

// Bytes uses CBOR to serialize the EnvelopeDescriptor.
func (e *EnvelopeDescriptor) Bytes() ([]byte, error) {
	blob, err := cbor.Marshal(e)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// EnvelopeDescriptorFromBytes uses CBOR to deserialize the EnvelopeDescriptor.
func EnvelopeDescriptorFromBytes(blob []byte) (*EnvelopeDescriptor, error) {
	var desc EnvelopeDescriptor
	err := cbor.Unmarshal(blob, &desc)
	if err != nil {
		return nil, err
	}
	return &desc, nil
}

// StoredEnvelopeData contains the envelope and associated box ID for reuse
type StoredEnvelopeData struct {
	Envelope *pigeonhole.CourierEnvelope
	BoxID    *[bacap.BoxIDSize]byte
}

// ChannelDescriptor describes a pigeonhole channel and supplies us with
// everthing we need to read or write to the channel.
type ChannelDescriptor struct {
	// AppID tracks which thin client owns this channel for cleanup purposes
	AppID *[AppIDLength]byte

	StatefulWriter     *bacap.StatefulWriter
	StatefulWriterLock sync.Mutex

	StatefulReader     *bacap.StatefulReader
	StatefulReaderLock sync.Mutex

	EnvelopeDescriptors     map[[hash.HashSize]byte]*EnvelopeDescriptor
	EnvelopeDescriptorsLock sync.RWMutex
}

func GetRandomCourier(doc *cpki.Document) (*[hash.HashSize]byte, []byte, error) {
	courierServices := common.FindServices(constants.CourierServiceName, doc)
	if len(courierServices) == 0 {
		return nil, nil, fmt.Errorf("no courier services found in PKI document")
	}
	courierService := courierServices[secureRand.Intn(len(courierServices))]
	serviceIdHash := hash.Sum256(courierService.MixDescriptor.IdentityKey)
	return &serviceIdHash, courierService.RecipientQueueID, nil
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

func CreateChannelWriteRequest(
	statefulWriter *bacap.StatefulWriter,
	payload []byte,
	doc *cpki.Document,
	geometry *pigeonholeGeo.Geometry) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {

	// Validate that the payload can fit within the geometry's MaxPlaintextPayloadLength
	// CreatePaddedPayload requires 4 bytes for length prefix plus the payload
	minRequiredSize := len(payload) + 4
	if minRequiredSize > geometry.MaxPlaintextPayloadLength+4 {
		return nil, nil, fmt.Errorf("payload too large: %d bytes (+ 4 byte length prefix) exceeds MaxPlaintextPayloadLength + 4 of %d bytes",
			len(payload), geometry.MaxPlaintextPayloadLength+4)
	}

	// Pad the payload to the geometry's MaxPlaintextPayloadLength + 4 to fill the user forward sphinx payloads
	paddedPayload, err := pigeonhole.CreatePaddedPayload(payload, geometry.MaxPlaintextPayloadLength+4)
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

	// Validate that the payload can fit within the geometry's MaxPlaintextPayloadLength
	// CreatePaddedPayload requires 4 bytes for length prefix plus the payload
	minRequiredSize := len(payload) + 4
	if minRequiredSize > geometry.MaxPlaintextPayloadLength+4 {
		return nil, nil, fmt.Errorf("payload too large: %d bytes (+ 4 byte length prefix) exceeds MaxPlaintextPayloadLength + 4 of %d bytes",
			len(payload), geometry.MaxPlaintextPayloadLength+4)
	}

	// Pad the payload to the geometry's MaxPlaintextPayloadLength + 4 to fill the user forward sphinx payloads
	paddedPayload, err := pigeonhole.CreatePaddedPayload(payload, geometry.MaxPlaintextPayloadLength+4)
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

func (d *Daemon) createWriteChannel(request *Request) {
	newWriteCap, err := bacap.NewWriteCap(rand.Reader)
	if err != nil {
		d.log.Errorf("createWriteChannel failure: %s", err)
		d.sendCreateWriteChannelError(request, thin.ThinClientImpossibleNewWriteCapError)
		return
	}
	statefulWriter, err := bacap.NewStatefulWriter(newWriteCap, constants.PIGEONHOLE_CTX)
	if err != nil {
		d.log.Errorf("createWriteChannel failure: %s", err)
		d.sendCreateWriteChannelError(request, thin.ThinClientImpossibleNewStatefulWriterError)
		return
	}
	channelID := d.generateUniqueChannelID()
	d.newChannelMapLock.Lock()
	d.newChannelMap[channelID] = &ChannelDescriptor{
		AppID:               request.AppID,
		StatefulWriter:      statefulWriter,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
	}
	d.newChannelMapLock.Unlock()
	writeCapBlob, err := newWriteCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("createWriteChannel failure: %s", err)
		d.sendCreateWriteChannelError(request, thin.ThinClientImpossibleNewWriteCapError)
		return
	}
	writeCapHash := hash.Sum256(writeCapBlob)
	d.capabilityLock.Lock()
	d.usedWriteCaps[writeCapHash] = true
	d.capabilityLock.Unlock()

	readCap := statefulWriter.Wcap.ReadCap()

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateWriteChannelReply: &thin.CreateWriteChannelReply{
			QueryID:   request.CreateWriteChannel.QueryID,
			ChannelID: channelID,
			ReadCap:   readCap,
			WriteCap:  statefulWriter.Wcap,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
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
			QueryID:   request.WriteChannel.QueryID,
			ChannelID: request.WriteChannel.ChannelID,
			ErrorCode: errorCode,
		}
	case "ReadChannel":
		response.ReadChannelReply = &thin.ReadChannelReply{
			QueryID:   request.ReadChannel.QueryID,
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

func validateReadChannelRequest(request *Request) error {
	if request.CreateReadChannel.QueryID == nil {
		return errors.New("QueryID is nil")
	}
	if request.CreateReadChannel.ReadCap == nil {
		return errors.New("ReadCap is nil")
	}
	return nil
}

func (d *Daemon) createReadChannel(request *Request) {
	err := validateReadChannelRequest(request)
	if err != nil {
		d.log.Errorf("createReadChannel failure: %s", err)
		d.sendCreateReadChannelError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	statefulReader, err := bacap.NewStatefulReader(request.CreateReadChannel.ReadCap, constants.PIGEONHOLE_CTX)
	if err != nil {
		d.log.Errorf("createReadChannel failure: %s", err)
		d.sendCreateReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	// note the read cap so that we cannot create duplicates
	readCapBlob, err := request.CreateReadChannel.ReadCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("createReadChannel failure: %s", err)
		d.sendCreateReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}
	readCapHash := hash.Sum256(readCapBlob)
	d.capabilityLock.Lock()
	_, ok := d.usedReadCaps[readCapHash]
	if ok {
		d.log.Errorf("createReadChannel failure: read cap already in use")
		d.sendCreateReadChannelError(request, thin.ThinClientCapabilityAlreadyInUse)
		d.capabilityLock.Unlock()
		return
	}
	d.usedReadCaps[readCapHash] = true
	d.capabilityLock.Unlock()

	channelID := d.generateUniqueChannelID()
	d.newChannelMapLock.Lock()
	d.newChannelMap[channelID] = &ChannelDescriptor{
		AppID:               request.AppID,
		StatefulReader:      statefulReader,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
	}
	d.newChannelMapLock.Unlock()

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("createReadChannel failure: "+errNoConnectionForAppID, request.AppID[:])
		d.sendCreateReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateReadChannelReply: &thin.CreateReadChannelReply{
			QueryID:   request.CreateReadChannel.QueryID,
			ChannelID: channelID,
			ErrorCode: thin.ThinClientSuccess,
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

func (d *Daemon) validateWriteChannelRequest(request *thin.WriteChannel) error {
	if request.QueryID == nil {
		return errors.New("QueryID is nil")
	}
	if request.ChannelID == 0 {
		return errors.New("ChannelID is 0")
	}
	if request.Payload == nil {
		return errors.New("Payload is nil")
	}
	return nil
}

func (d *Daemon) writeChannel(request *Request) {

	err := d.validateWriteChannelRequest(request.WriteChannel)
	if err != nil {
		d.log.Errorf("writeChannel failure: %s", err)
		d.sendWriteChannelError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	channelID := request.WriteChannel.ChannelID

	d.newChannelMapLock.RLock()
	channelDesc, ok := d.newChannelMap[channelID]
	d.newChannelMapLock.RUnlock()
	if !ok || channelDesc == nil {
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

	// Debug: Check if PigeonholeGeometry is nil
	if d.cfg.PigeonholeGeometry == nil {
		d.log.Errorf("writeChannel failure: PigeonholeGeometry is nil")
		d.sendWriteChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	channelDesc.StatefulWriterLock.Lock()

	// Debug: Log geometry and payload information
	d.log.Debugf("writeChannel: payload size=%d, geometry MaxPlaintextPayloadLength=%d",
		len(request.WriteChannel.Payload), d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength)
	d.log.Debugf("writeChannel: geometry NIKEName=%s", d.cfg.PigeonholeGeometry.NIKEName)

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
	envelopeDescriptorBytes, err := channelDesc.EnvelopeDescriptors[*envHash].Bytes()
	if err != nil {
		d.log.Errorf("writeChannel failure: failed to serialize envelope descriptor: %s", err)
		d.sendWriteChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		WriteChannelReply: &thin.WriteChannelReply{
			QueryID:             request.WriteChannel.QueryID,
			ChannelID:           channelID,
			SendMessagePayload:  courierQuery.Bytes(),
			CurrentMessageIndex: channelDesc.StatefulWriter.GetCurrentMessageIndex(),
			NextMessageIndex:    nextMessageIndex,
			EnvelopeHash:        envHash,
			EnvelopeDescriptor:  envelopeDescriptorBytes,
			ErrorCode:           thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) readChannel(request *Request) {
	channelID := request.ReadChannel.ChannelID

	d.newChannelMapLock.RLock()
	channelDesc, ok := d.newChannelMap[channelID]
	d.newChannelMapLock.RUnlock()

	if !ok || channelDesc == nil {
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

	// It is legit and possible to read the same BACAP box twice because you
	// want to read the replies of two different replicas because the first one
	// failed.
	if request.ReadChannel.MessageBoxIndex != nil {
		channelDesc.StatefulReader.NextIndex = request.ReadChannel.MessageBoxIndex
	}

	boxID, err := channelDesc.StatefulReader.NextBoxID()
	if err != nil {
		channelDesc.StatefulReaderLock.Unlock()
		d.log.Errorf("readChannel failure: failed to get next box ID: %s", err)
		d.sendReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}
	nextMessageIndex, err := channelDesc.StatefulReader.GetNextMessageIndex()
	currentMessageIndex := channelDesc.StatefulReader.GetCurrentMessageIndex()
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
	envelopeDescriptorBytes, err := channelDesc.EnvelopeDescriptors[*envHash].Bytes()
	if err != nil {
		d.log.Errorf("readChannel failure: failed to serialize envelope descriptor: %s", err)
		d.sendReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	conn.sendResponse(&Response{
		AppID: request.AppID,
		ReadChannelReply: &thin.ReadChannelReply{
			QueryID:             request.ReadChannel.QueryID,
			ChannelID:           channelID,
			ErrorCode:           thin.ThinClientSuccess,
			SendMessagePayload:  courierQuery.Bytes(),
			CurrentMessageIndex: currentMessageIndex,
			NextMessageIndex:    nextMessageIndex,
			ReplyIndex:          request.ReadChannel.ReplyIndex,
			EnvelopeHash:        envHash,
			EnvelopeDescriptor:  envelopeDescriptorBytes,
		},
	})
}

// closeChannel closes a pigeonhole channel and cleans up its resources
func (d *Daemon) closeChannel(request *Request) {
	d.log.Debug("closeChannel: closing channel")

	channelID := request.CloseChannel.ChannelID

	d.newChannelMapLock.Lock()
	channelDesc, ok := d.newChannelMap[channelID]
	if ok {
		delete(d.newChannelMap, channelID)
	}
	d.newChannelMapLock.Unlock()

	if !ok || channelDesc == nil {
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

	d.capabilityLock.Lock()
	switch {
	case channelDesc.StatefulReader != nil:
		readCapBlob, err := channelDesc.StatefulReader.Rcap.MarshalBinary()
		if err != nil {
			d.log.Errorf("closeChannel: failed to marshal read cap: %s", err)
			return
		}
		readCapHash := hash.Sum256(readCapBlob)
		delete(d.usedReadCaps, readCapHash)
	case channelDesc.StatefulWriter != nil:
		writeCapBlob, err := channelDesc.StatefulWriter.Wcap.MarshalBinary()
		if err != nil {
			d.log.Errorf("closeChannel: failed to marshal write cap: %s", err)
			return
		}
		writeCapHash := hash.Sum256(writeCapBlob)
		delete(d.usedWriteCaps, writeCapHash)
	}
	d.capabilityLock.Unlock()

	d.log.Infof("closeChannel: successfully closed channel %d", channelID)
}

// cleanupChannelsForAppID cleans up all channels associated with a given App ID
// This is called when a thin client disconnects to ensure proper cleanup
func (d *Daemon) cleanupChannelsForAppID(appID *[AppIDLength]byte) {
	d.log.Infof("cleanupChannelsForAppID: cleaning up channels for App ID %x", appID[:])

	// Acquire all locks in a consistent order to prevent deadlocks
	// Order: channelReplies -> newSurbIDToChannelMap -> newChannelMap
	d.channelRepliesLock.Lock()
	d.newSurbIDToChannelMapLock.Lock()
	d.newChannelMapLock.Lock()
	defer d.newChannelMapLock.Unlock()
	defer d.newSurbIDToChannelMapLock.Unlock()
	defer d.channelRepliesLock.Unlock()

	// Find all channels and SURB IDs that belong to this App ID
	channelsToCleanup := make(map[uint16]bool)
	surbIDsToDelete := make([][sphinxConstants.SURBIDLength]byte, 0)

	// First pass: find all channels that belong to this App ID directly
	for channelID, channelDesc := range d.newChannelMap {
		// Skip nil channel descriptors (these are placeholders from generateUniqueChannelID)
		if channelDesc == nil {
			continue
		}
		if channelDesc.AppID != nil && *channelDesc.AppID == *appID {
			channelsToCleanup[channelID] = true
		}
	}

	// Second pass: identify all SURB IDs that belong to this App ID
	for surbID, replyDesc := range d.channelReplies {
		if replyDesc.appID != nil && *replyDesc.appID == *appID {
			surbIDsToDelete = append(surbIDsToDelete, surbID)
			// Also mark any channels found via SURB mappings (defensive)
			if channelID, exists := d.newSurbIDToChannelMap[surbID]; exists {
				channelsToCleanup[channelID] = true
			}
		}
	}

	if len(channelsToCleanup) == 0 && len(surbIDsToDelete) == 0 {
		d.log.Debugf("cleanupChannelsForAppID: no channels or SURB mappings found for App ID %x", appID[:])
		return
	}

	d.log.Infof("cleanupChannelsForAppID: found %d channels and %d SURB mappings to clean up for App ID %x",
		len(channelsToCleanup), len(surbIDsToDelete), appID[:])

	// Clean up all identified resources atomically

	// Remove channels from channel map
	for channelID := range channelsToCleanup {
		if _, exists := d.newChannelMap[channelID]; exists {
			delete(d.newChannelMap, channelID)
			d.log.Debugf("cleanupChannelsForAppID: removed channel %d for App ID %x", channelID, appID[:])
		}
	}

	// Remove SURB ID to channel mappings for these channels
	surbIDMappingsToDelete := make([][sphinxConstants.SURBIDLength]byte, 0)
	for surbID, channelID := range d.newSurbIDToChannelMap {
		if channelsToCleanup[channelID] {
			surbIDMappingsToDelete = append(surbIDMappingsToDelete, surbID)
		}
	}
	for _, surbID := range surbIDMappingsToDelete {
		delete(d.newSurbIDToChannelMap, surbID)
	}

	// Remove channel replies for this App ID
	for _, surbID := range surbIDsToDelete {
		delete(d.channelReplies, surbID)
	}

	d.log.Infof("cleanupChannelsForAppID: completed cleanup of %d channels for App ID %x", len(channelsToCleanup), appID[:])
}
