// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica_service

import (
	"errors"

	"github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/pigeonhole"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

func (r *ReplicaService) OnCommand(cmd cborplugin.Command) error {
	request, ok := cmd.(*cborplugin.Request)
	if !ok {
		return errors.New("replica_service: received invalid Command type")
	}

	msg, err := pigeonhole.ParseReplicaInnerMessage(request.Payload)
	if err != nil {
		r.log.Errorf("Failed to parse ReplicaInnerMessage: %s", err)
		// Send error reply
		reply := r.createErrorReply()
		go r.sendReply(request, reply)
		return nil
	}

	var replyInner *pigeonhole.ReplicaMessageReplyInnerMessage

	switch {
	case msg.ReadMsg != nil:
		r.log.Debugf("Processing ReplicaRead for BoxID: %x", msg.ReadMsg.BoxID)
		readReply := r.handleRead(msg.ReadMsg)
		replyInner = &pigeonhole.ReplicaMessageReplyInnerMessage{
			ReadReply: readReply,
		}
	case msg.WriteMsg != nil:
		r.log.Debugf("Processing ReplicaWrite for BoxID: %x", msg.WriteMsg.BoxID)
		writeReply := r.handleWrite(msg.WriteMsg)
		replyInner = &pigeonhole.ReplicaMessageReplyInnerMessage{
			WriteReply: writeReply,
		}
	default:
		r.log.Error("Received message with neither Read nor Write")
		reply := r.createErrorReply()
		go r.sendReply(request, reply)
		return nil
	}

	go r.sendReply(request, replyInner.Bytes())
	return nil
}

func (r *ReplicaService) sendReply(request *cborplugin.Request, payload []byte) {
	r.write(&cborplugin.Response{
		ID:      request.ID,
		SURB:    request.SURB,
		Payload: payload,
	})
}

func (r *ReplicaService) createErrorReply() []byte {
	reply := &pigeonhole.ReplicaMessageReplyInnerMessage{
		WriteReply: &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorInternalError,
		},
	}
	return reply.Bytes()
}

func (r *ReplicaService) handleRead(replicaRead *pigeonhole.ReplicaRead) *pigeonhole.ReplicaReadReply {
	r.log.Debugf("Handling replica read request for BoxID: %x", replicaRead.BoxID)
	box, err := r.state.handleReplicaRead(replicaRead)

	switch {
	case err == nil:
		r.log.Debug("Replica read successful")
		return &pigeonhole.ReplicaReadReply{
			BoxID:      box.BoxID,
			Signature:  box.Signature,
			PayloadLen: uint32(len(box.Payload)),
			Payload:    box.Payload,
			ErrorCode:  pigeonhole.ReplicaSuccess,
		}
	case errors.Is(err, ErrBoxIDNotFound):
		r.log.Debug("Replica read: Box ID not found")
		// XXX TODO REPLICATION: When box not found locally, proxy read request
		// to remote shards that may have the data. See replica/handlers.go
		// proxyReadRequest() which dispatches to other replicas via connector.
		return &pigeonhole.ReplicaReadReply{
			BoxID:     replicaRead.BoxID,
			ErrorCode: pigeonhole.ReplicaErrorBoxIDNotFound,
		}
	default:
		r.log.Errorf("Replica read failed: %s", err)
		return &pigeonhole.ReplicaReadReply{
			ErrorCode: pigeonhole.ReplicaErrorDatabaseFailure,
		}
	}
}

func (r *ReplicaService) handleWrite(replicaWrite *pigeonhole.ReplicaWrite) *pigeonhole.ReplicaWriteReply {
	r.log.Debugf("Handling replica write request for BoxID: %x", replicaWrite.BoxID)

	// Verify signature
	s := ed25519.Scheme()
	verifyKey, err := s.UnmarshalBinaryPublicKey(replicaWrite.BoxID[:])
	if err != nil {
		r.log.Errorf("Failed to unmarshal BoxID as public key: %v", err)
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorInvalidBoxID,
		}
	}
	if !s.Verify(verifyKey, replicaWrite.Payload, replicaWrite.Signature[:], nil) {
		r.log.Error("Signature verification failed")
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorInvalidSignature,
		}
	}

	// Write to database
	err = r.state.handleReplicaWrite(replicaWrite)
	if err != nil {
		r.log.Errorf("Database write failed: %v", err)
		return &pigeonhole.ReplicaWriteReply{
			ErrorCode: pigeonhole.ReplicaErrorDatabaseFailure,
		}
	}

	// XXX TODO REPLICATION: After successful local write, dispatch write command
	// to remote shards for redundancy. See replica/handlers.go handleReplicaWrite()
	// which calls: c.l.server.connector.DispatchReplication(wireCmd)

	r.log.Debug("Replica write successful")
	return &pigeonhole.ReplicaWriteReply{
		ErrorCode: pigeonhole.ReplicaSuccess,
	}
}
