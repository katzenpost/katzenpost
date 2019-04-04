// remote_spool.go - client session remote spool operations
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

package session

import (
	"fmt"
	"strings"

	"github.com/katzenpost/client/multispool"
	"github.com/katzenpost/core/crypto/eddsa"
)

const OKStatus = "OK"

func (s *Session) submitCommand(cmd []byte, recipient, provider string) (*multispool.SpoolResponse, error) {
	id, err := s.SendUnreliableMessage(recipient, provider, cmd)
	if err != nil {
		return nil, err
	}
	reply, err := s.WaitForReply(id)
	if err != nil {
		return nil, err
	}
	spoolResponse, err := multispool.SpoolResponseFromBytes(reply)
	if err != nil {
		return nil, err
	}
	if strings.Compare(spoolResponse.Status, OKStatus) == 0 {
		return &spoolResponse, nil
	}

	return nil, fmt.Errorf("spool command failure: %s", spoolResponse.Status)
}

// SendCreateSpool is a work-in-progress right now.
func (s *Session) CreateSpool(privKey *eddsa.PrivateKey, recipient, provider string) (*[multispool.SpoolIDSize]byte, error) {
	cmd, err := multispool.CreateSpool(privKey)
	if err != nil {
		return nil, err
	}
	spoolResponse, err := s.submitCommand(cmd, recipient, provider)
	if err != nil {
		return nil, err
	}
	return &spoolResponse.SpoolID, nil
}

func (s *Session) PurgeSpool(spoolID [multispool.SpoolIDSize]byte, privKey *eddsa.PrivateKey, recipient, provider string) error {
	cmd, err := multispool.PurgeSpool(spoolID, privKey)
	if err != nil {
		return err
	}
	_, err = s.submitCommand(cmd, recipient, provider)
	return err
}

func (s *Session) AppendToSpool(spoolID [multispool.SpoolIDSize]byte, message []byte, recipient, provider string) error {
	cmd, err := multispool.AppendToSpool(spoolID, message)
	if err != nil {
		return err
	}
	_, err = s.submitCommand(cmd, recipient, provider)
	return err
}

func (s *Session) ReadFromSpool(spoolID [multispool.SpoolIDSize]byte, messageID [multispool.MessageIDSize]byte,
	privKey *eddsa.PrivateKey,
	recipient,
	provider string) (*multispool.SpoolResponse, error) {

	cmd, err := multispool.ReadFromSpool(spoolID, messageID, privKey)
	if err != nil {
		return nil, err
	}
	return s.submitCommand(cmd, recipient, provider)
}
