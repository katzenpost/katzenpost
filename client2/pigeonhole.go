// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"time"

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
	StatefulWriter      *bacap.StatefulWriter
	StatefulReader      *bacap.StatefulReader
	BoxOwnerCap         *bacap.BoxOwnerCap // Only set for write channels
	EnvelopeDescriptors map[[hash.HashSize]byte]*EnvelopeDescriptor
	EnvelopeLock        sync.RWMutex // Protects EnvelopeDescriptors map
	SendSeq             uint64

	// StoredEnvelopes maps message IDs to stored envelope data for reuse
	StoredEnvelopes     map[[thin.MessageIDLength]byte]*StoredEnvelopeData
	StoredEnvelopesLock sync.RWMutex // Protects StoredEnvelopes map

	// ReaderLock protects StatefulReader.DecryptNext calls to prevent BACAP state corruption
	// CRITICAL: DecryptNext advances the reader's internal state and must be serialized
	ReaderLock sync.Mutex

	// WriterLock protects StatefulWriter state advancement to prevent BACAP state corruption
	// CRITICAL: State advancement must be serialized and only happen after courier acknowledgment
	WriterLock sync.Mutex
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

func NewPigeonholeChannel() (*bacap.StatefulWriter, *bacap.UniversalReadCap, *bacap.BoxOwnerCap) {
	owner, err := bacap.NewBoxOwnerCap(rand.Reader)
	if err != nil {
		panic(err)
	}
	statefulWriter, err := bacap.NewStatefulWriter(owner, constants.PIGEONHOLE_CTX)
	if err != nil {
		panic(err)
	}
	bobReadCap := owner.UniversalReadCap()
	return statefulWriter, bobReadCap, owner
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
	boxID, ciphertext, sigraw := statefulWriter.NextIndex.EncryptForContext(statefulWriter.Owner, statefulWriter.Ctx, paddedPayload)

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

// advanceWriterToIndex advances a StatefulWriter to the specified target index
func (d *Daemon) advanceWriterToIndex(statefulWriter *bacap.StatefulWriter, targetIndex *bacap.MessageBoxIndex) error {
	if targetIndex == nil {
		return nil
	}

	// Advance to the target index if needed
	for statefulWriter.NextIndex.Idx64 < targetIndex.Idx64 {
		nextIndex, err := statefulWriter.NextIndex.NextIndex()
		if err != nil {
			return fmt.Errorf("failed to advance to target index: %s", err)
		}
		statefulWriter.LastOutboxIdx = statefulWriter.NextIndex
		statefulWriter.NextIndex = nextIndex
	}
	return nil
}

// advanceReaderToIndex advances a StatefulReader to the specified target index
func (d *Daemon) advanceReaderToIndex(statefulReader *bacap.StatefulReader, targetIndex *bacap.MessageBoxIndex) error {
	if targetIndex == nil {
		return nil
	}

	// Advance to the target index if needed
	for statefulReader.NextIndex.Idx64 < targetIndex.Idx64 {
		nextIndex, err := statefulReader.NextIndex.NextIndex()
		if err != nil {
			return fmt.Errorf("failed to advance to target index: %s", err)
		}
		statefulReader.LastInboxRead = statefulReader.NextIndex
		statefulReader.NextIndex = nextIndex
	}
	return nil
}

// setupWriteChannelFromExisting creates a StatefulWriter from an existing BoxOwnerCap
func (d *Daemon) setupWriteChannelFromExisting(request *Request) (*bacap.StatefulWriter, *bacap.UniversalReadCap, *bacap.BoxOwnerCap, error) {
	boxOwnerCap := request.CreateWriteChannel.BoxOwnerCap
	bobReadCap := boxOwnerCap.UniversalReadCap()

	// Create StatefulWriter from the provided BoxOwnerCap
	statefulWriter, err := bacap.NewStatefulWriter(boxOwnerCap, constants.PIGEONHOLE_CTX)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create StatefulWriter: %s", err)
	}

	// Advance to the specified index if provided
	if err := d.advanceWriterToIndex(statefulWriter, request.CreateWriteChannel.MessageBoxIndex); err != nil {
		return nil, nil, nil, err
	}

	return statefulWriter, bobReadCap, boxOwnerCap, nil
}

// setupWriteChannelFromNew creates a new channel and StatefulWriter
func (d *Daemon) setupWriteChannelFromNew(request *Request) (*bacap.StatefulWriter, *bacap.UniversalReadCap, *bacap.BoxOwnerCap, error) {
	// Creating new channel
	statefulWriter, bobReadCap, boxOwnerCap := NewPigeonholeChannel()

	// Advance to the specified index if provided
	if err := d.advanceWriterToIndex(statefulWriter, request.CreateWriteChannel.MessageBoxIndex); err != nil {
		return nil, nil, nil, err
	}

	return statefulWriter, bobReadCap, boxOwnerCap, nil
}

// storeWriteChannelDescriptor stores the channel descriptor in the daemon's channel map
func (d *Daemon) storeWriteChannelDescriptor(channelID [thin.ChannelIDLength]byte, statefulWriter *bacap.StatefulWriter, boxOwnerCap *bacap.BoxOwnerCap) {
	d.channelMapLock.Lock()
	defer d.channelMapLock.Unlock()

	d.channelMap[channelID] = &ChannelDescriptor{
		StatefulWriter:      statefulWriter,
		BoxOwnerCap:         boxOwnerCap,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[thin.MessageIDLength]byte]*StoredEnvelopeData),
	}
}

// sendWriteChannelSuccessResponse sends a successful response for write channel creation
func (d *Daemon) sendWriteChannelSuccessResponse(request *Request, channelID [thin.ChannelIDLength]byte, bobReadCap *bacap.UniversalReadCap, boxOwnerCap *bacap.BoxOwnerCap, currentMessageIndex *bacap.MessageBoxIndex) {
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
			BoxOwnerCap:      boxOwnerCap,
			NextMessageIndex: currentMessageIndex,
		},
	})
}

func (d *Daemon) createWriteChannel(request *Request) {
	// Setup channel components based on whether we're resuming or creating new
	var statefulWriter *bacap.StatefulWriter
	var bobReadCap *bacap.UniversalReadCap
	var boxOwnerCap *bacap.BoxOwnerCap
	var err error

	isResuming := request.CreateWriteChannel.BoxOwnerCap != nil
	if isResuming {
		statefulWriter, bobReadCap, boxOwnerCap, err = d.setupWriteChannelFromExisting(request)
	} else {
		statefulWriter, bobReadCap, boxOwnerCap, err = d.setupWriteChannelFromNew(request)
	}

	if err != nil {
		d.log.Errorf("createWriteChannel failure: %s", err)
		d.sendWriteChannelError(request, err.Error())
		return
	}

	// Check for capability deduplication
	if err := d.checkWriteCapabilityDedup(request, boxOwnerCap); err != nil {
		return
	}

	// Generate channel ID
	channelID := [thin.ChannelIDLength]byte{}
	if _, err := rand.Reader.Read(channelID[:]); err != nil {
		panic(err)
	}

	// Store channel descriptor
	d.storeWriteChannelDescriptor(channelID, statefulWriter, boxOwnerCap)

	// Send success response
	currentMessageIndex := statefulWriter.NextIndex
	d.sendWriteChannelSuccessResponse(request, channelID, bobReadCap, boxOwnerCap, currentMessageIndex)
}

func (d *Daemon) createReadChannel(request *Request) {
	// Check for capability deduplication first
	if err := d.checkReadCapabilityDedup(request, request.CreateReadChannel.ReadCap); err != nil {
		return
	}

	// Create a new channelID for Bob's read channel
	channelID := [thin.ChannelIDLength]byte{}
	_, err := rand.Reader.Read(channelID[:])
	if err != nil {
		panic(err)
	}

	// Create a StatefulReader from the readCap provided by Alice
	statefulReader, err := bacap.NewStatefulReader(request.CreateReadChannel.ReadCap, constants.PIGEONHOLE_CTX)
	if err != nil {
		d.log.Errorf("createReadChannel failure: failed to create StatefulReader: %s", err)
		return
	}

	// If a specific MessageBoxIndex was provided, advance to that position
	if request.CreateReadChannel.MessageBoxIndex != nil {
		if err := d.advanceReaderToIndex(statefulReader, request.CreateReadChannel.MessageBoxIndex); err != nil {
			d.log.Errorf("createReadChannel failure: %s", err)
			return
		}
	}

	// Note: Capability deduplication for read channels is already handled at the beginning of createReadChannel

	// Create a new ChannelDescriptor for Bob's read channel
	d.channelMapLock.Lock()
	d.channelMap[channelID] = &ChannelDescriptor{
		StatefulReader:      statefulReader,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[thin.MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.channelMapLock.Unlock()

	// Get current message index for the reply
	currentMessageIndex := statefulReader.NextIndex

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("createReadChannel failure: "+errNoConnectionForAppID, request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateReadChannelReply: &thin.CreateReadChannelReply{
			ChannelID:        channelID,
			NextMessageIndex: currentMessageIndex,
		},
	})
}

func (d *Daemon) writeChannel(request *Request) {
	channelID := request.WriteChannel.ChannelID

	// Hold channelMapLock for the entire operation to ensure channelDesc doesn't change
	d.channelMapLock.RLock()
	channelDesc, ok := d.channelMap[channelID]
	if !ok {
		d.channelMapLock.RUnlock()
		d.log.Errorf("writeChannel failure: no channel found for channelID %x", channelID[:])
		conn := d.listener.getConnection(request.AppID)
		if conn != nil {
			conn.sendResponse(&Response{
				AppID: request.AppID,
				WriteChannelReply: &thin.WriteChannelReply{
					ChannelID: channelID,
					Err:       "channel not found",
				},
			})
		}
		return
	}
	// Keep the lock held while we work with channelDesc
	defer d.channelMapLock.RUnlock()

	_, doc := d.client.CurrentDocument()

	// Prepare the write request WITHOUT sending it and WITHOUT advancing state
	courierEnvelope, envelopePrivateKey, err := CreateChannelWriteRequestPrepareOnly(
		channelDesc.StatefulWriter,
		request.WriteChannel.Payload,
		doc,
		d.cfg.PigeonholeGeometry)

	if err != nil {
		d.log.Errorf("writeChannel failure: failed to create write request: %s", err)
		conn := d.listener.getConnection(request.AppID)
		if conn != nil {
			conn.sendResponse(&Response{
				AppID: request.AppID,
				WriteChannelReply: &thin.WriteChannelReply{
					ChannelID: channelID,
					Err:       err.Error(),
				},
			})
		}
		return
	}

	// Store envelope descriptor for later use when the message is actually sent
	envHash := courierEnvelope.EnvelopeHash()
	channelDesc.EnvelopeLock.Lock()
	channelDesc.EnvelopeDescriptors[*envHash] = &EnvelopeDescriptor{
		Epoch:       doc.Epoch,
		ReplicaNums: courierEnvelope.IntermediateReplicas,
		EnvelopeKey: envelopePrivateKey.Bytes(),
	}
	channelDesc.EnvelopeLock.Unlock()

	// Wrap CourierEnvelope in CourierQuery to create the SendMessage payload
	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}

	// Get the next MessageBoxIndex that will be used AFTER courier acknowledgment
	nextMessageIndex, err := channelDesc.StatefulWriter.NextIndex.NextIndex()
	if err != nil {
		d.log.Errorf("writeChannel failure: failed to get next message index: %s", err)
		conn := d.listener.getConnection(request.AppID)
		if conn != nil {
			conn.sendResponse(&Response{
				AppID: request.AppID,
				WriteChannelReply: &thin.WriteChannelReply{
					ChannelID: channelID,
					Err:       err.Error(),
				},
			})
		}
		return
	}

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		WriteChannelReply: &thin.WriteChannelReply{
			ChannelID:          channelID,
			SendMessagePayload: courierQuery.Bytes(),
			NextMessageIndex:   nextMessageIndex,
		},
	})
}

// getOrCreateEnvelope retrieves a stored envelope or creates a new one for the read request
func (d *Daemon) getOrCreateEnvelope(request *Request, channelDesc *ChannelDescriptor, doc *cpki.Document) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {
	// Check if we have a stored envelope for this message ID
	if request.ReadChannel.ID != nil {
		if envelope, privateKey, found := d.getStoredEnvelope(request.ReadChannel.ID, channelDesc); found {
			return envelope, privateKey, nil
		}
	}

	// Create a new envelope if we don't have a stored one
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
	channelDesc.EnvelopeLock.RLock()
	mapSize := len(channelDesc.EnvelopeDescriptors)
	envDesc, envExists := channelDesc.EnvelopeDescriptors[*envHash]
	channelDesc.EnvelopeLock.RUnlock()

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

// createNewEnvelope creates a new courier envelope for the read request
func (d *Daemon) createNewEnvelope(request *Request, channelDesc *ChannelDescriptor, doc *cpki.Document) (*pigeonhole.CourierEnvelope, nike.PrivateKey, error) {
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
	if request.ReadChannel.ID != nil {
		channelDesc.StoredEnvelopesLock.Lock()
		channelDesc.StoredEnvelopes[*request.ReadChannel.ID] = &StoredEnvelopeData{
			Envelope: courierEnvelope,
			BoxID:    boxID,
		}
		channelDesc.StoredEnvelopesLock.Unlock()
		d.log.Debugf("Stored envelope for message ID %x", request.ReadChannel.ID[:])
	}

	return courierEnvelope, envelopePrivateKey, nil
}

// sendReadChannelErrorResponse sends an error response for a read channel request
func (d *Daemon) sendReadChannelErrorResponse(request *Request, channelID [thin.ChannelIDLength]byte, errorMsg string) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			ReadChannelReply: &thin.ReadChannelReply{
				MessageID: request.ReadChannel.ID,
				ChannelID: channelID,
				Err:       errorMsg,
			},
		})
	}
}

// storeEnvelopeDescriptor stores the envelope descriptor for new envelopes (not reused ones)
func (d *Daemon) storeEnvelopeDescriptor(courierEnvelope *pigeonhole.CourierEnvelope, envelopePrivateKey nike.PrivateKey, channelDesc *ChannelDescriptor, doc *cpki.Document) error {
	envHash := courierEnvelope.EnvelopeHash()

	// DEBUG: Log envelope hash and map size when storing
	channelDesc.EnvelopeLock.RLock()
	mapSize := len(channelDesc.EnvelopeDescriptors)
	channelDesc.EnvelopeLock.RUnlock()
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
	channelDesc.EnvelopeLock.RLock()
	_, envDescExists := channelDesc.EnvelopeDescriptors[*envHash]
	channelDesc.EnvelopeLock.RUnlock()

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
		channelDesc.EnvelopeLock.Lock()
		channelDesc.EnvelopeDescriptors[*envHash] = &EnvelopeDescriptor{
			Epoch:       doc.Epoch, // Store normal epoch, convert when needed
			ReplicaNums: courierEnvelope.IntermediateReplicas,
			EnvelopeKey: envelopeKey,
		}
		channelDesc.EnvelopeLock.Unlock()
	}
	return nil
}

// sendEnvelopeToCourier sends the courier envelope via Sphinx and sets up reply handling
func (d *Daemon) sendEnvelopeToCourier(request *Request, channelID [thin.ChannelIDLength]byte, courierEnvelope *pigeonhole.CourierEnvelope, doc *cpki.Document) error {
	surbid := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbid[:])
	if err != nil {
		return fmt.Errorf("failed to generate SURB ID: %s", err)
	}

	destinationIdHash, recipientQueueID := GetRandomCourier(doc)

	// Wrap CourierEnvelope in CourierQuery
	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}

	sendRequest := &Request{
		AppID: request.AppID,
		SendMessage: &thin.SendMessage{
			ID:                request.ReadChannel.ID,
			WithSURB:          true,
			DestinationIdHash: destinationIdHash,
			RecipientQueueID:  recipientQueueID,
			Payload:           courierQuery.Bytes(),
			SURBID:            surbid,
		},
	}

	surbKey, rtt, err := d.client.SendCiphertext(sendRequest)
	if err != nil {
		return fmt.Errorf("failed to send sphinx packet: %s", err)
	}

	// Set up reply handling
	fetchInterval := d.client.GetPollInterval()
	slop := time.Second
	duration := rtt + fetchInterval + slop
	replyArrivalTime := time.Now().Add(duration)

	d.channelRepliesLock.Lock()
	d.channelReplies[*surbid] = replyDescriptor{
		ID:      request.ReadChannel.ID,
		appID:   request.AppID,
		surbKey: surbKey,
	}
	d.channelRepliesLock.Unlock()

	d.surbIDToChannelMapLock.Lock()
	d.surbIDToChannelMap[*surbid] = channelID
	d.surbIDToChannelMapLock.Unlock()

	d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), sendRequest.SendMessage.SURBID)

	return nil
}

// sendReadChannelSuccessResponse sends a success response for a read channel request
func (d *Daemon) sendReadChannelSuccessResponse(request *Request, channelID [thin.ChannelIDLength]byte) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ReadChannelReply: &thin.ReadChannelReply{
			MessageID: request.ReadChannel.ID,
			ChannelID: channelID,
		},
	})
}

func (d *Daemon) readChannel(request *Request) {
	channelID := request.ReadChannel.ChannelID

	// Hold channelMapLock for the entire operation to ensure channelDesc doesn't change
	d.channelMapLock.RLock()
	channelDesc, ok := d.channelMap[channelID]
	if !ok {
		d.channelMapLock.RUnlock()
		d.log.Errorf("no channel found for channelID %x", channelID[:])
		conn := d.listener.getConnection(request.AppID)
		if conn != nil {
			conn.sendResponse(&Response{
				AppID: request.AppID,
				ReadChannelReply: &thin.ReadChannelReply{
					MessageID: request.ReadChannel.ID,
					ChannelID: channelID,
					Err:       "channel not found",
				},
			})
		}
		return
	}
	// Keep the lock held while we work with channelDesc
	defer d.channelMapLock.RUnlock()

	_, doc := d.client.CurrentDocument()

	// Get or create the courier envelope WITHOUT sending it
	courierEnvelope, envelopePrivateKey, err := d.getOrCreateEnvelope(request, channelDesc, doc)
	if err != nil {
		d.log.Errorf("failed to get or create envelope: %s", err)
		conn := d.listener.getConnection(request.AppID)
		if conn != nil {
			conn.sendResponse(&Response{
				AppID: request.AppID,
				ReadChannelReply: &thin.ReadChannelReply{
					MessageID: request.ReadChannel.ID,
					ChannelID: channelID,
					Err:       err.Error(),
				},
			})
		}
		return
	}

	// Store envelope descriptor for later use when the message is actually sent
	err = d.storeEnvelopeDescriptor(courierEnvelope, envelopePrivateKey, channelDesc, doc)
	if err != nil {
		d.log.Errorf("failed to store envelope descriptor: %s", err)
		conn := d.listener.getConnection(request.AppID)
		if conn != nil {
			conn.sendResponse(&Response{
				AppID: request.AppID,
				ReadChannelReply: &thin.ReadChannelReply{
					MessageID: request.ReadChannel.ID,
					ChannelID: channelID,
					Err:       err.Error(),
				},
			})
		}
		return
	}

	// Wrap CourierEnvelope in CourierQuery to create the SendMessage payload
	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}

	// Get the next MessageBoxIndex that will be used AFTER successful read
	nextMessageIndex, err := channelDesc.StatefulReader.NextIndex.NextIndex()
	if err != nil {
		d.log.Errorf("failed to get next message index: %s", err)
		conn := d.listener.getConnection(request.AppID)
		if conn != nil {
			conn.sendResponse(&Response{
				AppID: request.AppID,
				ReadChannelReply: &thin.ReadChannelReply{
					MessageID: request.ReadChannel.ID,
					ChannelID: channelID,
					Err:       err.Error(),
				},
			})
		}
		return
	}

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ReadChannelReply: &thin.ReadChannelReply{
			MessageID:          request.ReadChannel.ID,
			ChannelID:          channelID,
			SendMessagePayload: courierQuery.Bytes(),
			NextMessageIndex:   nextMessageIndex,
		},
	})
}

// sendWriteChannelError sends an error response for write channel creation
func (d *Daemon) sendWriteChannelError(request *Request, errorMsg string) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			CreateWriteChannelReply: &thin.CreateWriteChannelReply{
				ChannelID: [thin.ChannelIDLength]byte{},
				Err:       errorMsg,
			},
		})
	}
}

// sendReadChannelError sends an error response for read channel creation
func (d *Daemon) sendReadChannelError(request *Request, errorMsg string) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			CreateReadChannelReply: &thin.CreateReadChannelReply{
				ChannelID: [thin.ChannelIDLength]byte{},
				Err:       errorMsg,
			},
		})
	}
}

// checkWriteCapabilityDedup checks if a BoxOwnerCap is already in use and adds it to the dedup map
func (d *Daemon) checkWriteCapabilityDedup(request *Request, boxOwnerCap *bacap.BoxOwnerCap) error {
	boxOwnerCapBytes, err := boxOwnerCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("createWriteChannel failure: failed to marshal BoxOwnerCap: %s", err)
		d.sendWriteChannelError(request, errCapabilityMarshalFailed)
		return err
	}

	capKey := string(boxOwnerCapBytes)
	d.capabilityLock.Lock()
	defer d.capabilityLock.Unlock()

	if d.usedWriteCaps[capKey] {
		d.log.Errorf("createWriteChannel failure: BoxOwnerCap already in use")
		d.sendWriteChannelError(request, errCapabilityAlreadyInUse)
		return fmt.Errorf(errCapabilityAlreadyInUse)
	}

	// Mark this capability as used
	d.usedWriteCaps[capKey] = true
	return nil
}

// checkReadCapabilityDedup checks if a UniversalReadCap is already in use and adds it to the dedup map
func (d *Daemon) checkReadCapabilityDedup(request *Request, readCap *bacap.UniversalReadCap) error {
	readCapBytes, err := readCap.MarshalBinary()
	if err != nil {
		d.log.Errorf("createReadChannel failure: failed to marshal UniversalReadCap: %s", err)
		d.sendReadChannelError(request, errCapabilityMarshalFailed)
		return err
	}

	capKey := string(readCapBytes)
	d.capabilityLock.Lock()
	defer d.capabilityLock.Unlock()

	if d.usedReadCaps[capKey] {
		d.log.Errorf("createReadChannel failure: UniversalReadCap already in use")
		d.sendReadChannelError(request, errCapabilityAlreadyInUse)
		return fmt.Errorf(errCapabilityAlreadyInUse)
	}

	// Mark this capability as used
	d.usedReadCaps[capKey] = true
	return nil
}

// removeCapabilityFromDedup removes a capability from the deduplication maps
// This should be called when a channel is explicitly closed or removed
func (d *Daemon) removeCapabilityFromDedup(channelDesc *ChannelDescriptor) {
	d.capabilityLock.Lock()
	defer d.capabilityLock.Unlock()

	// Remove write capability if this is a write channel
	if channelDesc.BoxOwnerCap != nil {
		boxOwnerCapBytes, err := channelDesc.BoxOwnerCap.MarshalBinary()
		if err == nil {
			capKey := string(boxOwnerCapBytes)
			delete(d.usedWriteCaps, capKey)
		}
	}

	// Remove read capability if this is a read channel
	if channelDesc.StatefulReader != nil {
		readCapBytes, err := channelDesc.StatefulReader.Urcap.MarshalBinary()
		if err == nil {
			capKey := string(readCapBytes)
			delete(d.usedReadCaps, capKey)
		}
	}
}
