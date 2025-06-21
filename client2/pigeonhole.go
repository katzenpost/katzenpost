// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

var (
	// Package-level cryptographically secure random number generator
	secureRand = rand.NewMath()
)

const (
	// Error message for missing connection
	errNoConnectionForAppID = "no connection associated with AppID %x"

	// Error messages for capability deduplication
	errCapabilityMarshalFailed = "failed to marshal capability"
	errCapabilityAlreadyInUse  = "capability already in use"
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

	intermediateReplicas, replicaPubKeys, err := pigeonhole.GetRandomIntermediateReplicas(doc)
	if err != nil {
		return nil, nil, err
	}

	// Use the shared envelope creation function
	return pigeonhole.CreateWriteEnvelope(
		boxIDArray,
		sigArray,
		ciphertext,
		replicaPubKeys,
		intermediateReplicas,
		doc.Epoch,
		replicaCommon.MKEMNikeScheme,
	)
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

	intermediateReplicas, replicaPubKeys, err := pigeonhole.GetRandomIntermediateReplicas(doc)
	if err != nil {
		return nil, nil, err
	}

	sigArray := [64]uint8{}
	copy(sigArray[:], sigraw)

	boxIDArray := [32]uint8{}
	copy(boxIDArray[:], boxID[:])

	return pigeonhole.CreateWriteEnvelope(
		boxIDArray,
		sigArray,
		ciphertext,
		replicaPubKeys,
		intermediateReplicas,
		doc.Epoch,
		replicaCommon.MKEMNikeScheme,
	)
}

func CreateChannelReadRequest(channelID uint16,
	statefulReader *bacap.StatefulReader,
	doc *cpki.Document) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {

	boxID, err := statefulReader.NextBoxID()
	if err != nil {
		panic(err)
	}

	return CreateChannelReadRequestWithBoxID(channelID, boxID, doc)
}

func CreateChannelReadRequestWithBoxID(channelID uint16,
	boxID *[bacap.BoxIDSize]byte,
	doc *cpki.Document) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {

	// Convert boxID to array
	var boxIDArray [32]uint8
	copy(boxIDArray[:], boxID[:])

	intermediateReplicas, replicaPubKeys, err := pigeonhole.GetRandomIntermediateReplicas(doc)
	if err != nil {
		return nil, nil, err
	}

	// DEBUG: Log Bob's read operation
	fmt.Printf("BOB MKEM ENCRYPT: Starting encryption for read request\n")

	// Use the shared envelope creation function
	envelope, mkemPrivateKey, err := pigeonhole.CreateReadEnvelope(
		boxIDArray,
		replicaPubKeys,
		intermediateReplicas,
		doc.Epoch,
		replicaCommon.MKEMNikeScheme,
	)
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
	d.channelMapLock.Lock()
	d.channelMap[channelID] = &ChannelDescriptor{
		StatefulWriter:      statefulWriter,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[thin.MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.channelMapLock.Unlock()

	currentMessageIndex := statefulWriter.NextIndex
	bobReadCap := statefulWriter.Wcap.ReadCap()
	d.sendWriteChannelSuccessResponse(request, channelID, bobReadCap, statefulWriter.Wcap, currentMessageIndex)
}

func (d *Daemon) createReadChannel(request *Request) {
	statefulReader, err := d.createOrResumeStatefulReader(request)
	if err != nil {
		d.log.Errorf("createReadChannel failure: %s", err)
		d.sendCreateReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	channelID := d.generateUniqueChannelID()
	d.channelMapLock.Lock()
	d.channelMap[channelID] = &ChannelDescriptor{
		StatefulReader:      statefulReader,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[thin.MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.channelMapLock.Unlock()

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

func (d *Daemon) writeChannel(request *Request) {
	channelID := request.WriteChannel.ChannelID

	d.channelMapLock.RLock()
	channelDesc, ok := d.channelMap[channelID]
	d.channelMapLock.RUnlock()
	if !ok {
		d.channelMapLock.RUnlock()
		d.log.Errorf("writeChannel failure: no channel found for channelID %d", channelID)
		d.sendWriteChannelError(request, thin.ThinClientErrorChannelNotFound)
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

// getOrCreateEnvelope retrieves a stored envelope or creates a new one for the read request
func (d *Daemon) getOrCreateEnvelope(request *Request, channelDesc *ChannelDescriptor, doc *cpki.Document) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {
	if envelope, privateKey, found := d.getStoredEnvelope(request.ReadChannel.MessageID, channelDesc); found {
		return envelope, privateKey, nil
	}
	return d.createNewEnvelope(request, channelDesc, doc)
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
	envDesc, envExists := channelDesc.EnvelopeDescriptors[*envHash]
	channelDesc.EnvelopeDescriptorsLock.RUnlock()

	if !envExists {
		d.log.Errorf("envelope descriptor not found for stored envelope")
		return nil, nil, false
	}

	envelopePrivateKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPrivateKey(envDesc.EnvelopeKey)
	if err != nil {
		d.log.Errorf("failed to unmarshal stored envelope private key: %s", err)
		return nil, nil, false
	}

	return courierEnvelope, envelopePrivateKey, true
}

// createNewEnvelope creates a new courier envelope for the read request
func (d *Daemon) createNewEnvelope(request *Request, channelDesc *ChannelDescriptor, doc *cpki.Document) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {
	// CRITICAL: Protect StatefulReader state access with ReaderLock to prevent BACAP state corruption
	channelDesc.StatefulReaderLock.Lock()
	defer channelDesc.StatefulReaderLock.Unlock()

	boxID, err := channelDesc.StatefulReader.NextBoxID()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get next box ID: %s", err)
	}

	// DEBUG: Log Bob's read BoxID
	fmt.Printf("BOB READS FROM BoxID: %x\n", boxID[:])
	fmt.Fprintf(os.Stderr, "BOB READS FROM BoxID: %x\n", boxID[:])

	courierEnvelope, envelopePrivateKey, err := CreateChannelReadRequestWithBoxID(
		request.ReadChannel.ChannelID,
		boxID,
		doc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create read request: %s", err)
	}

	// Store the envelope and box ID for future reuse if we have a message ID
	if request.ReadChannel.MessageID != nil {
		channelDesc.StoredEnvelopesLock.Lock()
		channelDesc.StoredEnvelopes[*request.ReadChannel.MessageID] = &StoredEnvelopeData{
			Envelope: courierEnvelope,
			BoxID:    boxID,
		}
		channelDesc.StoredEnvelopesLock.Unlock()
		d.log.Debugf("Stored envelope for message ID %x", request.ReadChannel.MessageID[:])
	}

	return courierEnvelope, envelopePrivateKey, nil
}

func (d *Daemon) storeEnvelopeDescriptor(courierEnvelope *pigeonhole.CourierEnvelope, envelopePrivateKey nike.PrivateKey, channelDesc *ChannelDescriptor, doc *cpki.Document) error {
	pubKeyLen := len(courierEnvelope.SenderPubkey)
	if pubKeyLen > 32 {
		pubKeyLen = 32
	}
	cipherLen := len(courierEnvelope.Ciphertext)
	if cipherLen > 32 {
		cipherLen = 32
	}

	envHash := courierEnvelope.EnvelopeHash()

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
			Epoch:       doc.Epoch,
			ReplicaNums: courierEnvelope.IntermediateReplicas,
			EnvelopeKey: envelopeKey,
		}
		channelDesc.EnvelopeDescriptorsLock.Unlock()
	}
	return nil
}

func (d *Daemon) readChannel(request *Request) {
	channelID := request.ReadChannel.ChannelID

	d.channelMapLock.RLock()
	channelDesc, ok := d.channelMap[channelID]
	d.channelMapLock.RUnlock()

	if !ok {
		d.log.Errorf("no channel found for channelID %d", channelID)
		d.sendReadChannelError(request, thin.ThinClientErrorChannelNotFound)
		return
	}

	_, doc := d.client.CurrentDocument()

	courierEnvelope, envelopePrivateKey, err := d.getOrCreateEnvelope(request, channelDesc, doc)
	if err != nil {
		d.log.Errorf("failed to get or create envelope: %s", err)
		d.sendReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	err = d.storeEnvelopeDescriptor(courierEnvelope, envelopePrivateKey, channelDesc, doc)
	if err != nil {
		d.log.Errorf("failed to store envelope descriptor: %s", err)
		d.sendReadChannelError(request, thin.ThinClientErrorInternalError)
		return
	}

	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}

	channelDesc.StatefulReaderLock.Lock()
	nextMessageIndex, err := channelDesc.StatefulReader.NextIndex.NextIndex()
	channelDesc.StatefulReaderLock.Unlock()

	if err != nil {
		d.log.Errorf("failed to get next message index: %s", err)
		d.sendReadChannelError(request, thin.ThinClientErrorInternalError)
		return
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
		},
	})
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
		statefulWriter, err = bacap.NewStatefulWriter(request.CreateWriteChannel.WriteCap, constants.PIGEONHOLE_CTX)
		if err != nil {
			return nil, err
		}
	}

	return statefulWriter, nil
}

func (d *Daemon) createOrResumeStatefulReader(request *Request) (*bacap.StatefulReader, error) {
	isResuming := request.CreateReadChannel.ReadCap != nil
	var statefulReader *bacap.StatefulReader
	var err error
	if isResuming {
		if err := d.checkReadCapabilityDedup(request, request.CreateReadChannel.ReadCap); err != nil {
			return nil, err
		}
		if request.CreateReadChannel.MessageBoxIndex == nil {
			statefulReader, err = bacap.NewStatefulReader(request.CreateReadChannel.ReadCap, constants.PIGEONHOLE_CTX)
			if err != nil {
				return nil, err
			}
		} else {
			statefulReader, err = bacap.NewStatefulReaderWithIndex(
				request.CreateReadChannel.ReadCap,
				constants.PIGEONHOLE_CTX,
				request.CreateReadChannel.MessageBoxIndex)
			if err != nil {
				return nil, err
			}
		}
	} else {
		statefulReader, err = bacap.NewStatefulReader(request.CreateReadChannel.ReadCap, constants.PIGEONHOLE_CTX)
		if err != nil {
			return nil, err
		}
	}

	return statefulReader, nil
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
		return errors.New(errCapabilityAlreadyInUse)
	}

	// Mark this capability as used
	d.usedWriteCaps[capHash] = true
	return nil
}

// checkReadCapabilityDedup checks if a ReadCap is already in use and adds it to the dedup map
func (d *Daemon) checkReadCapabilityDedup(request *Request, readCap *bacap.ReadCap) error {
	readCapBytes, err := readCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("createReadChannel failure: failed to marshal ReadCap: %s", err)
		d.sendReadChannelError(request, thin.ThinClientErrorInternalError)
		return err
	}

	capHash := hash.Sum256(readCapBytes)
	d.capabilityLock.Lock()
	defer d.capabilityLock.Unlock()

	if d.usedReadCaps[capHash] {
		d.log.Errorf("createReadChannel failure: ReadCap already in use")
		d.sendReadChannelError(request, thin.ThinClientErrorInvalidRequest)
		return errors.New(errCapabilityAlreadyInUse)
	}

	// Mark this capability as used
	d.usedReadCaps[capHash] = true
	return nil
}

// removeCapabilityFromDedup removes a capability from the deduplication maps
// This should be called when a channel is explicitly closed or removed
func (d *Daemon) removeCapabilityFromDedup(channelDesc *ChannelDescriptor) {
	if channelDesc.StatefulReader != nil {
		readCapBytes, err := channelDesc.StatefulReader.Rcap.MarshalBinary()
		if err == nil {
			capHash := hash.Sum256(readCapBytes)
			d.capabilityLock.Lock()
			delete(d.usedReadCaps, capHash)
			d.capabilityLock.Unlock()
		}
		return
	}
	if channelDesc.StatefulWriter != nil {
		boxOwnerCapBytes, err := channelDesc.StatefulWriter.Wcap.MarshalBinary()
		if err == nil {
			capHash := hash.Sum256(boxOwnerCapBytes)
			d.capabilityLock.Lock()
			delete(d.usedWriteCaps, capHash)
			d.capabilityLock.Unlock()
		}
	}
}

func (d *Daemon) sendCreateWriteChannelError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			CreateWriteChannelReply: &thin.CreateWriteChannelReply{
				ChannelID: 0,
				ErrorCode: errorCode,
			},
		})
	}
}

func (d *Daemon) sendCreateReadChannelError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			CreateReadChannelReply: &thin.CreateReadChannelReply{
				ChannelID: 0,
				ErrorCode: errorCode,
			},
		})
	}
}

func (d *Daemon) sendReadChannelError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			ReadChannelReply: &thin.ReadChannelReply{
				MessageID: request.ReadChannel.MessageID,
				ChannelID: request.ReadChannel.ChannelID,
				ErrorCode: errorCode,
			},
		})
	}
}

func (d *Daemon) sendWriteChannelError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			WriteChannelReply: &thin.WriteChannelReply{
				ChannelID: request.WriteChannel.ChannelID,
				ErrorCode: errorCode,
			},
		})
	}
}
