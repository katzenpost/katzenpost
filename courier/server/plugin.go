// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/courier/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

type Courier struct {
	write  func(cborplugin.Command)
	server *Server
}

// StartPlugin starts the CBOR plugin service which listens for socket connections
// from the service node.
func (s *Server) StartPlugin() {
	socketFile := filepath.Join(s.cfg.DataDir, fmt.Sprintf("%d.courier.socket", os.Getpid()))
	courier := &Courier{
		server: s,
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
	switch r := cmd.(type) {
	case *cborplugin.Request:
		courierMessage, err := common.CourierEnvelopeFromBytes(r.Payload)
		if err != nil {
			return err
		}

		replicas := make([]*commands.ReplicaMessage, 2)

		// replica 1
		firstReplicaID := courierMessage.Replicas[0]
		replicas[0] = &commands.ReplicaMessage{
			SenderEPubKey: courierMessage.SenderEPubKey[0],
			DEK:           courierMessage.DEK[0],
			Ciphertext:    courierMessage.Ciphertext,
		}
		e.server.SendMessage(firstReplicaID, replicas[0])

		// replica 2
		secondReplicaID := courierMessage.Replicas[1]
		replicas[1] = &commands.ReplicaMessage{
			SenderEPubKey: courierMessage.SenderEPubKey[1],
			DEK:           courierMessage.DEK[1],
			Ciphertext:    courierMessage.Ciphertext,
		}
		e.server.SendMessage(secondReplicaID, replicas[1])

		replyPayload := []byte{} // XXX FIX ME
		go func() {
			// send reply
			e.write(&cborplugin.Response{ID: r.ID, SURB: r.SURB, Payload: replyPayload})
		}()
		return nil
	default:
		return errors.New("courier-plugin: Invalid Command type")
	}
}

func (e *Courier) RegisterConsumer(s *cborplugin.Server) {
	e.write = s.Write
}
