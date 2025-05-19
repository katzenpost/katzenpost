// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

type Courier struct {
	write  func(cborplugin.Command)
	server *Server

	cmds           *commands.Commands
	geo            *geo.Geometry
	envelopeScheme nike.Scheme
}

// StartPlugin starts the CBOR plugin service which listens for socket connections
// from the service node.
func (s *Server) StartPlugin() {
	socketFile := filepath.Join(s.cfg.DataDir, fmt.Sprintf("%d.courier.socket", os.Getpid()))

	scheme := schemes.ByName(s.cfg.EnvelopeScheme)
	cmds := commands.NewStorageReplicaCommands(s.cfg.SphinxGeometry, scheme)

	courier := &Courier{
		server: s,

		cmds:           cmds,
		geo:            s.cfg.SphinxGeometry,
		envelopeScheme: scheme,
	}
	var server *cborplugin.Server

	server = cborplugin.NewServer(s.LogBackend().GetLogger("courier_plugin"), socketFile, new(cborplugin.RequestFactory), courier)
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	err := os.Remove(socketFile)
	if err != nil {
		panic(err)
	}

}

func (e *Courier) OnCommand(cmd cborplugin.Command) error {
	e.server.log.Debug("---------- OnCommand BEGIN")
	switch r := cmd.(type) {
	case *cborplugin.Request:
		courierMessage, err := common.CourierEnvelopeFromBytes(r.Payload)
		if err != nil {
			e.server.log.Debugf("---------- CBOR DECODE FAIL: %s", err)
			return err
		}

		replicas := make([]*commands.ReplicaMessage, 2)

		// replica 1
		e.server.log.Debug("---------- OnCommand: proxying to replica1")
		firstReplicaID := courierMessage.IntermediateReplicas[0]
		replicas[0] = &commands.ReplicaMessage{
			Cmds:   e.cmds,
			Geo:    e.geo,
			Scheme: e.envelopeScheme,

			SenderEPubKey: courierMessage.SenderEPubKey,
			DEK:           courierMessage.DEK[0],
			Ciphertext:    courierMessage.Ciphertext,
		}
		e.server.SendMessage(firstReplicaID, replicas[0])

		// replica 2
		e.server.log.Debug("---------- OnCommand: proxying to replica2")
		secondReplicaID := courierMessage.IntermediateReplicas[1]
		replicas[1] = &commands.ReplicaMessage{
			Cmds:   e.cmds,
			Geo:    e.geo,
			Scheme: e.envelopeScheme,

			SenderEPubKey: courierMessage.SenderEPubKey,
			DEK:           courierMessage.DEK[1],
			Ciphertext:    courierMessage.Ciphertext,
		}
		e.server.SendMessage(secondReplicaID, replicas[1])

		envelopeHash := courierMessage.EnvelopeHash()
		reply := &common.CourierEnvelopeReply{
			EnvelopeHash: envelopeHash,
			ReplyIndex:   0,
			Payload:      &commands.ReplicaMessageReply{},
			ErrorString:  "",
			ErrorCode:    0,
		}
		replyPayload := reply.Bytes()

		e.server.log.Debug("---------- OnCommand END... sending reply")

		go func() {
			// send reply
			e.write(&cborplugin.Response{
				ID:      r.ID,
				SURB:    r.SURB,
				Payload: replyPayload,
			})
		}()
		return nil
	default:
		return errors.New("---------- courier-plugin: Invalid Command type")
	}
}

func (e *Courier) RegisterConsumer(s *cborplugin.Server) {
	e.write = s.Write
}
