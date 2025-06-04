// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	mrand "math/rand"
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

func CreateChannelWriteRequest(channelID [thin.ChannelIDLength]byte, statefulWriter *bacap.StatefulWriter, payload []byte) (*replicaCommon.CourierEnvelope, nike.PrivateKey) {
	boxID, ciphertext, sigraw, err := statefulWriter.EncryptNext(payload)
	if err != nil {
		panic(err)
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

	replicaPubKeys := make([]nike.PublicKey, 2)

	mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes(),
	)
	mkemPublicKey := mkemPrivateKey.Public()

	envelope := &replicaCommon.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext:           mkemCiphertext.Envelope,
	}
	return envelope, mkemPrivateKey
}

func CreateChannelReadRequest(channelID [thin.ChannelIDLength]byte,
	statefulReader *bacap.StatefulReader,
	doc *cpki.Document) (*replicaCommon.CourierEnvelope, nike.PrivateKey, error) {

	boxID, err := statefulReader.NextBoxID()
	if err != nil {
		panic(err)
	}

	readRequest := &replicaCommon.ReplicaRead{
		BoxID: boxID,
	}

	msg := &replicaCommon.ReplicaInnerMessage{
		ReplicaRead: readRequest,
	}

	replicaPubKeys := make([]nike.PublicKey, 2)
	maxReplica := uint8(len(doc.StorageReplicas) - 1)

	// select two random replicas
	replica1 := uint8(mrand.Intn(int(maxReplica)))
	var replica2 uint8
	for replica2 == replica1 {
		replica2 = uint8(mrand.Intn(int(maxReplica)))
	}

	intermediateReplicas := [2]uint8{uint8(replica1), uint8(replica2)}
	desc1, err := replicaCommon.ReplicaNum(replica1, doc)
	if err != nil {
		return nil, nil, err
	}
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	replicaPubKeys0Blob := desc1.EnvelopeKeys[replicaEpoch]
	replicaPubKeys[0], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKeys0Blob)
	if err != nil {
		return nil, nil, err
	}

	desc2, err := replicaCommon.ReplicaNum(replica2, doc)
	if err != nil {
		return nil, nil, err
	}
	replicaPubKeys1Blob := desc2.EnvelopeKeys[replicaEpoch]
	replicaPubKeys[1], err = replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKeys1Blob)
	if err != nil {
		return nil, nil, err
	}

	mkemPrivateKey, mkemCiphertext := replicaCommon.MKEMNikeScheme.Encapsulate(
		replicaPubKeys, msg.Bytes(),
	)
	mkemPublicKey := mkemPrivateKey.Public()

	envelope := &replicaCommon.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
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
		StatefulWriter: statefulWriter,
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
	channelID := [thin.ChannelIDLength]byte{}
	_, err := rand.Reader.Read(channelID[:])
	if err != nil {
		panic(err)
	}
	d.channelMapLock.Lock()
	channelDesc, ok := d.channelMap[channelID]
	if !ok {
		d.log.Errorf("no channel found for channelID %x", channelID[:])
		return
	}
	statefulReader, err := bacap.NewStatefulReader(request.CreateReadChannel.ReadCap, constants.PIGEONHOLE_CTX)
	if err != nil {
		panic(err)
	}
	channelDesc.StatefulReader = statefulReader
	d.channelMapLock.Unlock()

	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf("no connection associated with AppID %x", request.AppID[:])
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
	if !ok {
		d.log.Errorf("no channel found for channelID %x", channelID[:])
		return
	}
	d.channelMapLock.RUnlock()

	courierEnvelope, envelopePrivateKey := CreateChannelWriteRequest(
		request.WriteChannel.ChannelID,
		channelDesc.StatefulWriter,
		request.WriteChannel.Payload)

	envHash := courierEnvelope.EnvelopeHash()
	channelDesc.EnvelopeDescriptors[*envHash].EnvelopeKey = envelopePrivateKey.Bytes()

	// XXX FIX ME TODO: send to courier
	//d.SendToCourier(courierEnvelope)

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
	if doc == nil {
		d.log.Errorf("no pki doc found")
		return
	}

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
	channelDesc.EnvelopeDescriptors[*envHash] = &EnvelopeDescriptor{
		Epoch:       replicaEpoch,
		ReplicaNums: courierEnvelope.IntermediateReplicas,
		EnvelopeKey: envelopeKey,
	}

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
