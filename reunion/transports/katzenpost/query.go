// query.go - Reunion client query transport for Katzenpost mix network.
// Copyright (C) 2019  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package katzenpost provides the client ACN transport for Reunion
// DB queries on a katzenpost decryption mix network.
package katzenpost

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/reunion/commands"
)

// Transport is used by Reunion protocol
// clients to send queries to the Reunion DB service.
type Transport struct {
	// Session is a thin client which
	// can be used to send mixnet messages.
	Session *thin.ThinClient
	// Recipient is the destination service.
	Recipient []byte
	// Provider is the destination Provider.
	Provider string
}

// CurrentSharedRandoms returns the valid SharedRandoms in the PKI
// but in the future may return a transport specific SharedRandom
func (k *Transport) CurrentSharedRandoms() ([][]byte, error) {
	doc := k.Session.PKIDocument()
	return doc.PriorSharedRandom, nil
}

// CurrentEpochs returns the valid Epochs that this service has announced
func (k *Transport) CurrentEpochs() ([]uint64, error) {
	parmToEpochs := func(epochstr string) []uint64 {
		epochsAsc := strings.Split(strings.Trim(epochstr, "[]"), ",")
		epochs := make([]uint64, 0)
		for _, e := range epochsAsc {
			epoch, err := strconv.Atoi(strings.Trim(e, " "))
			if err != nil {
				return nil
			}
			epochs = append(epochs, uint64(epoch))
		}
		return epochs
	}

	// Verify the service is still advertising valid epochs in the current PKI
	doc := k.Session.PKIDocument()
	p, err := doc.GetGateway(k.Provider)
	if err != nil {
		return nil, errors.New("Provider not found in PKI")
	}
	if ep, ok := p.Kaetzchen["reunion"]; ok {
		if parm, ok := ep["epoch"]; ok {
			if epochs := parmToEpochs(parm.(string)); epochs != nil {
				return epochs, nil
			}
			return nil, errors.New("No valid epochs found in descriptor")
		}
		return nil, errors.New("Providers Reunion descriptor il formatted")
	}
	return nil, errors.New("Reunion endpoint not found in PKI")
}

// Query sends the command to the destination Reunion DB service
// over a Katzenpost mix network.
func (k *Transport) Query(command commands.Command) (commands.Command, error) {
	mesgID := k.Session.NewMessageID()
	doc := k.Session.PKIDocument()
	providerKey, err := doc.GetServiceNode(k.Provider)
	if err != nil {
		return nil, err
	}
	id := hash.Sum256(providerKey.IdentityKey)
	reply, err := k.Session.BlockingSendReliableMessage(mesgID, command.ToBytes(), &id, k.Recipient)
	if err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, errors.New("error, reply is nil")
	}
	replyLen := binary.BigEndian.Uint32(reply[:4])
	cmd, err := commands.FromBytes(reply[4 : 4+replyLen])
	if err != nil {
		return nil, fmt.Errorf("Katzenpost Transport Query failure, cannot decode command in reply len %d, %s", replyLen, err.Error())
	}
	return cmd, nil
}
