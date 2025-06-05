// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"fmt"
	mrand "math/rand"
	"os"
	"sync"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
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
	Envelope *replicaCommon.CourierEnvelope
	BoxID    *[bacap.BoxIDSize]byte
}

// ChannelDescriptor describes a pigeonhole channel and supplies us with
// everthing we need to read or write to the channel.
type ChannelDescriptor struct {
	StatefulWriter      *bacap.StatefulWriter
	StatefulReader      *bacap.StatefulReader
	EnvelopeDescriptors map[[hash.HashSize]byte]*EnvelopeDescriptor
	EnvelopeLock        sync.RWMutex // Protects EnvelopeDescriptors map
	SendSeq             uint64

	// StoredEnvelopes maps message IDs to stored envelope data for reuse
	StoredEnvelopes     map[[thin.MessageIDLength]byte]*StoredEnvelopeData
	StoredEnvelopesLock sync.RWMutex // Protects StoredEnvelopes map

	// ReaderLock protects StatefulReader.DecryptNext calls to prevent BACAP state corruption
	// CRITICAL: DecryptNext advances the reader's internal state and must be serialized
	ReaderLock sync.Mutex
}

func GetRandomCourier(doc *cpki.Document) (*[hash.HashSize]byte, []byte) {
	courierServices := common.FindServices(constants.CourierServiceName, doc)
	if len(courierServices) == 0 {
		panic("wtf no courier services")
	}
	courierService := courierServices[mrand.Intn(len(courierServices))]
	serviceIdHash := hash.Sum256(courierService.MixDescriptor.IdentityKey)
	return &serviceIdHash, courierService.RecipientQueueID
}

func GetRandomIntermediateReplicas(doc *cpki.Document) ([2]uint8, []nike.PublicKey, error) {
	maxReplica := uint8(len(doc.StorageReplicas) - 1)
	replica1 := uint8(mrand.Intn(int(maxReplica)))
	var replica2 uint8
	for replica2 == replica1 {
		replica2 = uint8(mrand.Intn(int(maxReplica)))
	}

	replicaPubKeys := make([]nike.PublicKey, 2)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	for i, replicaNum := range [2]uint8{replica1, replica2} {
		desc, err := replicaCommon.ReplicaNum(replicaNum, doc)
		if err != nil {
			return [2]uint8{}, nil, err
		}
		replicaPubKeys[i], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(desc.EnvelopeKeys[replicaEpoch])
		if err != nil {
			return [2]uint8{}, nil, err
		}
	}
	return [2]uint8{replica1, replica2}, replicaPubKeys, nil
}

func NewPigeonholeChannel() (*bacap.StatefulWriter, *bacap.UniversalReadCap) {
	owner, err := bacap.NewBoxOwnerCap(rand.Reader)
	if err != nil {
		panic(err)
	}
	statefulWriter, err := bacap.NewStatefulWriter(owner, constants.PIGEONHOLE_CTX)
	if err != nil {
		panic(err)
	}
	bobReadCap := owner.UniversalReadCap()
	return statefulWriter, bobReadCap
}

func CreateChannelWriteRequest(
	channelID [thin.ChannelIDLength]byte,
	statefulWriter *bacap.StatefulWriter,
	payload []byte,
	doc *cpki.Document) (*replicaCommon.CourierEnvelope, nike.PrivateKey, error) {

	boxID, ciphertext, sigraw, err := statefulWriter.EncryptNext(payload)
	if err != nil {
		return nil, nil, err
	}

	// DEBUG: Log Alice's write BoxID
	fmt.Printf("ALICE WRITES TO BoxID: %x\n", boxID[:])
	fmt.Fprintf(os.Stderr, "ALICE WRITES TO BoxID: %x\n", boxID[:])

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	writeRequest := commands.ReplicaWrite{
		BoxID:     &boxID,
		Signature: &sig,
		Payload:   ciphertext,
	}
	msg := &replicaCommon.ReplicaInnerMessage{
		ReplicaWrite: &writeRequest,
	}

	intermediateReplicas, replicaPubKeys, err := GetRandomIntermediateReplicas(doc)
	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("ALICE MKEM ENCRYPT: Starting encryption with message size %d bytes\n", len(msg.Bytes()))
	mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes(),
	)
	mkemPublicKey := mkemPrivateKey.Public()

	// DEBUG: Log Alice's MKEM private key for envelope creation
	mkemPrivateKeyBytes, _ := mkemPrivateKey.MarshalBinary()
	fmt.Printf("ALICE CREATES ENVELOPE WITH MKEM KEY: %x\n", mkemPrivateKeyBytes[:16]) // First 16 bytes for brevity
	fmt.Printf("ALICE MKEM ENCRYPT SUCCESS: Encrypted to %d bytes\n", len(mkemCiphertext.Envelope))

	envelope := &replicaCommon.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		Epoch:                doc.Epoch,
		IntermediateReplicas: intermediateReplicas,
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext:           mkemCiphertext.Envelope,
	}
	return envelope, mkemPrivateKey, err
}

func CreateChannelReadRequest(channelID [thin.ChannelIDLength]byte,
	statefulReader *bacap.StatefulReader,
	doc *cpki.Document) (*replicaCommon.CourierEnvelope, nike.PrivateKey, error) {

	boxID, err := statefulReader.NextBoxID()
	if err != nil {
		panic(err)
	}

	return CreateChannelReadRequestWithBoxID(channelID, boxID, doc)
}

func CreateChannelReadRequestWithBoxID(channelID [thin.ChannelIDLength]byte,
	boxID *[bacap.BoxIDSize]byte,
	doc *cpki.Document) (*replicaCommon.CourierEnvelope, nike.PrivateKey, error) {

	msg := &replicaCommon.ReplicaInnerMessage{
		ReplicaRead: &replicaCommon.ReplicaRead{
			BoxID: boxID,
		},
	}

	intermediateReplicas, replicaPubKeys, err := GetRandomIntermediateReplicas(doc)
	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("BOB MKEM ENCRYPT: Starting encryption with message size %d bytes\n", len(msg.Bytes()))
	mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(replicaPubKeys, msg.Bytes())

	// DEBUG: Log Bob's MKEM private key for envelope creation
	mkemPrivateKeyBytes, _ := mkemPrivateKey.MarshalBinary()
	fmt.Printf("BOB CREATES ENVELOPE WITH MKEM KEY: %x\n", mkemPrivateKeyBytes[:16]) // First 16 bytes for brevity
	fmt.Printf("BOB MKEM ENCRYPT SUCCESS: Encrypted to %d bytes\n", len(mkemCiphertext.Envelope))

	envelope := &replicaCommon.CourierEnvelope{
		SenderEPubKey:        mkemPrivateKey.Public().Bytes(),
		Epoch:                doc.Epoch,
		IntermediateReplicas: intermediateReplicas,
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               true,
	}
	return envelope, mkemPrivateKey, nil
}

func (d *Daemon) createChannel(request *Request) {
	statefulWriter, bobReadCap := NewPigeonholeChannel()
	channelID := [thin.ChannelIDLength]byte{}
	_, err := rand.Reader.Read(channelID[:])
	if err != nil {
		panic(err)
	}
	d.channelMapLock.Lock()
	d.channelMap[channelID] = &ChannelDescriptor{
		StatefulWriter:      statefulWriter,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[thin.MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.channelMapLock.Unlock()

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateChannelReply: &thin.CreateChannelReply{
			ChannelID: channelID,
			ReadCap:   bobReadCap,
		},
	})
}

func (d *Daemon) createReadChannel(request *Request) {
	// Create a new channelID for Bob's read channel
	channelID := [thin.ChannelIDLength]byte{}
	_, err := rand.Reader.Read(channelID[:])
	if err != nil {
		panic(err)
	}

	// Create a StatefulReader from the readCap provided by Alice
	statefulReader, err := bacap.NewStatefulReader(request.CreateReadChannel.ReadCap, constants.PIGEONHOLE_CTX)
	if err != nil {
		panic(err)
	}

	// Create a new ChannelDescriptor for Bob's read channel
	d.channelMapLock.Lock()
	d.channelMap[channelID] = &ChannelDescriptor{
		StatefulReader:      statefulReader,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[thin.MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.channelMapLock.Unlock()

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("createReadChannel failure: no connection associated with AppID %x", request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CreateReadChannelReply: &thin.CreateReadChannelReply{
			ChannelID: channelID,
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
		return
	}
	// Keep the lock held while we work with channelDesc
	defer d.channelMapLock.RUnlock()

	_, doc := d.client.CurrentDocument()

	courierEnvelope, envelopePrivateKey, err := CreateChannelWriteRequest(
		request.WriteChannel.ChannelID,
		channelDesc.StatefulWriter,
		request.WriteChannel.Payload,
		doc)

	if err != nil {
		d.log.Errorf("writeChannel failure: failed to create write request: %s", err)
		return
	}

	envHash := courierEnvelope.EnvelopeHash()
	channelDesc.EnvelopeLock.Lock()
	channelDesc.EnvelopeDescriptors[*envHash] = &EnvelopeDescriptor{
		Epoch:       doc.Epoch,
		ReplicaNums: courierEnvelope.IntermediateReplicas,
		EnvelopeKey: envelopePrivateKey.Bytes(),
	}
	channelDesc.EnvelopeLock.Unlock()

	surbid := &[sphinxConstants.SURBIDLength]byte{}
	_, err = rand.Reader.Read(surbid[:])
	if err != nil {
		panic(err)
	}
	destinationIdHash, recipientQueueID := GetRandomCourier(doc)
	sendRequest := &Request{
		ID:                request.ID,
		AppID:             request.AppID,
		WithSURB:          true,
		DestinationIdHash: destinationIdHash,
		RecipientQueueID:  recipientQueueID,
		Payload:           courierEnvelope.Bytes(),
		SURBID:            surbid,
		IsSendOp:          true,
	}
	surbKey, rtt, err := d.client.SendCiphertext(sendRequest)
	if err != nil {
		d.log.Errorf("failed to send sphinx packet: %s", err.Error())
		// Send error response to client
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

	fetchInterval := d.client.GetPollInterval()
	slop := time.Second
	duration := rtt + fetchInterval + slop
	replyArrivalTime := time.Now().Add(duration)

	d.channelRepliesLock.Lock()
	d.channelReplies[*surbid] = replyDescriptor{
		appID:   request.AppID,
		surbKey: surbKey,
	}
	d.channelRepliesLock.Unlock()

	d.surbIDToChannelMapLock.Lock()
	d.surbIDToChannelMap[*surbid] = channelID
	d.surbIDToChannelMapLock.Unlock()

	d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), sendRequest.SURBID)

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		WriteChannelReply: &thin.WriteChannelReply{
			ChannelID: channelID,
		},
	})
}

// getOrCreateEnvelope retrieves a stored envelope or creates a new one for the read request
func (d *Daemon) getOrCreateEnvelope(request *Request, channelDesc *ChannelDescriptor, doc *cpki.Document) (*replicaCommon.CourierEnvelope, nike.PrivateKey, error) {
	// Check if we have a stored envelope for this message ID
	if request.ID != nil {
		if envelope, privateKey, found := d.getStoredEnvelope(request.ID, channelDesc); found {
			return envelope, privateKey, nil
		}
	}

	// Create a new envelope if we don't have a stored one
	return d.createNewEnvelope(request, channelDesc, doc)
}

// getStoredEnvelope retrieves a previously stored envelope and its private key
// Returns the envelope, private key, and a boolean indicating if found
func (d *Daemon) getStoredEnvelope(messageID *[thin.MessageIDLength]byte, channelDesc *ChannelDescriptor) (*replicaCommon.CourierEnvelope, nike.PrivateKey, bool) {
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
func (d *Daemon) createNewEnvelope(request *Request, channelDesc *ChannelDescriptor, doc *cpki.Document) (*replicaCommon.CourierEnvelope, nike.PrivateKey, error) {
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
	if request.ID != nil {
		channelDesc.StoredEnvelopesLock.Lock()
		channelDesc.StoredEnvelopes[*request.ID] = &StoredEnvelopeData{
			Envelope: courierEnvelope,
			BoxID:    boxID,
		}
		channelDesc.StoredEnvelopesLock.Unlock()
		d.log.Debugf("Stored envelope for message ID %x", request.ID[:])
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
				ChannelID: channelID,
				Err:       errorMsg,
			},
		})
	}
}

// storeEnvelopeDescriptor stores the envelope descriptor for new envelopes (not reused ones)
func (d *Daemon) storeEnvelopeDescriptor(courierEnvelope *replicaCommon.CourierEnvelope, envelopePrivateKey nike.PrivateKey, channelDesc *ChannelDescriptor, doc *cpki.Document) error {
	envHash := courierEnvelope.EnvelopeHash()

	// DEBUG: Log envelope hash and map size when storing
	channelDesc.EnvelopeLock.RLock()
	mapSize := len(channelDesc.EnvelopeDescriptors)
	channelDesc.EnvelopeLock.RUnlock()
	fmt.Printf("STORING ENVELOPE HASH: %x (map size: %d)\n", envHash[:], mapSize)

	// DEBUG: Log the raw data being hashed to identify the issue
	fmt.Printf("DEBUG ENVELOPE DATA:\n")
	pubKeyLen := len(courierEnvelope.SenderEPubKey)
	if pubKeyLen > 32 {
		pubKeyLen = 32
	}
	cipherLen := len(courierEnvelope.Ciphertext)
	if cipherLen > 32 {
		cipherLen = 32
	}
	fmt.Printf("  SenderEPubKey: %x\n", courierEnvelope.SenderEPubKey[:pubKeyLen])
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
func (d *Daemon) sendEnvelopeToCourier(request *Request, channelID [thin.ChannelIDLength]byte, courierEnvelope *replicaCommon.CourierEnvelope, doc *cpki.Document) error {
	surbid := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbid[:])
	if err != nil {
		return fmt.Errorf("failed to generate SURB ID: %s", err)
	}

	destinationIdHash, recipientQueueID := GetRandomCourier(doc)

	sendRequest := &Request{
		ID:                request.ID,
		AppID:             request.AppID,
		WithSURB:          true,
		DestinationIdHash: destinationIdHash,
		RecipientQueueID:  recipientQueueID,
		Payload:           courierEnvelope.Bytes(),
		SURBID:            surbid,
		IsSendOp:          true,
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
		ID:      request.ID,
		appID:   request.AppID,
		surbKey: surbKey,
	}
	d.channelRepliesLock.Unlock()

	d.surbIDToChannelMapLock.Lock()
	d.surbIDToChannelMap[*surbid] = channelID
	d.surbIDToChannelMapLock.Unlock()

	d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), sendRequest.SURBID)

	return nil
}

// sendReadChannelSuccessResponse sends a success response for a read channel request
func (d *Daemon) sendReadChannelSuccessResponse(request *Request, channelID [thin.ChannelIDLength]byte) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		ReadChannelReply: &thin.ReadChannelReply{
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
		return
	}
	// Keep the lock held while we work with channelDesc
	defer d.channelMapLock.RUnlock()

	_, doc := d.client.CurrentDocument()

	// Get or create the courier envelope
	courierEnvelope, envelopePrivateKey, err := d.getOrCreateEnvelope(request, channelDesc, doc)
	if err != nil {
		d.log.Errorf("failed to get or create envelope: %s", err)
		d.sendReadChannelErrorResponse(request, channelID, err.Error())
		return
	}

	// Store envelope descriptor for new envelopes (not reused ones)
	err = d.storeEnvelopeDescriptor(courierEnvelope, envelopePrivateKey, channelDesc, doc)
	if err != nil {
		d.log.Errorf("failed to store envelope descriptor: %s", err)
		d.sendReadChannelErrorResponse(request, channelID, err.Error())
		return
	}

	// Send the envelope to the courier and handle the response
	err = d.sendEnvelopeToCourier(request, channelID, courierEnvelope, doc)
	if err != nil {
		d.log.Errorf("failed to send envelope to courier: %s", err)
		d.sendReadChannelErrorResponse(request, channelID, err.Error())
		return
	}

	// Send success response to client
	d.sendReadChannelSuccessResponse(request, channelID)
}
