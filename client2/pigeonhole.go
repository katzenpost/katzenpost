// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	mrand "math/rand"
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

// ChannelDescriptor describes a pigeonhole channel and supplies us with
// everthing we need to read or write to the channel.
type ChannelDescriptor struct {
	StatefulWriter      *bacap.StatefulWriter
	StatefulReader      *bacap.StatefulReader
	EnvelopeDescriptors map[[hash.HashSize]byte]*EnvelopeDescriptor
	EnvelopeLock        sync.RWMutex // Protects EnvelopeDescriptors map
	SendSeq             uint64
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
	mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes(),
	)
	mkemPublicKey := mkemPrivateKey.Public()

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

	msg := &replicaCommon.ReplicaInnerMessage{
		ReplicaRead: &replicaCommon.ReplicaRead{
			BoxID: boxID,
		},
	}

	intermediateReplicas, replicaPubKeys, err := GetRandomIntermediateReplicas(doc)
	if err != nil {
		return nil, nil, err
	}
	mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(replicaPubKeys, msg.Bytes())

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
	d.channelMapLock.RLock()
	channelDesc, ok := d.channelMap[channelID]
	d.channelMapLock.RUnlock()
	if !ok {
		d.log.Errorf("writeChannel failure: no channel found for channelID %x", channelID[:])
		return
	}

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

func (d *Daemon) readChannel(request *Request) {
	channelID := request.ReadChannel.ChannelID
	d.channelMapLock.RLock()
	channelDesc, ok := d.channelMap[channelID]
	d.channelMapLock.RUnlock()
	if !ok {
		d.log.Errorf("no channel found for channelID %x", channelID[:])
		return
	}

	_, doc := d.client.CurrentDocument()

	courierEnvelope, envelopePrivateKey, err := CreateChannelReadRequest(
		request.ReadChannel.ChannelID,
		channelDesc.StatefulReader,
		doc)
	if err != nil {
		d.log.Errorf("failed to create read request: %s", err)
		return
	}

	envHash := courierEnvelope.EnvelopeHash()
	replicaPubKeys := make([]nike.PublicKey, 2)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	for i, replicaNum := range courierEnvelope.IntermediateReplicas {
		desc, err := replicaCommon.ReplicaNum(replicaNum, doc)
		if err != nil {
			d.log.Errorf("failed to get replica descriptor: %s", err)
			return
		}
		replicaPubKeys[i], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(desc.EnvelopeKeys[replicaEpoch])
		if err != nil {
			d.log.Errorf("failed to unmarshal public key: %s", err)
			return
		}
	}

	envelopeKey, err := envelopePrivateKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	channelDesc.EnvelopeLock.Lock()
	channelDesc.EnvelopeDescriptors[*envHash] = &EnvelopeDescriptor{
		Epoch:       doc.Epoch, // Store normal epoch, convert when needed
		ReplicaNums: courierEnvelope.IntermediateReplicas,
		EnvelopeKey: envelopeKey,
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
				ReadChannelReply: &thin.ReadChannelReply{
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
		ReadChannelReply: &thin.ReadChannelReply{
			ChannelID: channelID,
		},
	})
}
