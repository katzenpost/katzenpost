// client.go - client session with remote spool operations
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

package client

import (
	"errors"
	"fmt"
	"strings"

	"github.com/katzenpost/client/session"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/memspool/common"
)

const (
	OKStatus         = "OK"
	SpoolServiceName = "spool"
)

type SpoolService interface {
	CreateSpool(privateKey *eddsa.PrivateKey, spoolReceiver string, spoolProvider string) ([]byte, error)
	ReadFromSpool(spoolID []byte, count uint32, privateKey *eddsa.PrivateKey, spoolReceiver string, spoolProvider string) (*common.SpoolResponse, error)
	AppendToSpool(spoolID []byte, message []byte, spoolReceiver string, spoolProvider string) error
	PurgeSpool(spoolID []byte, privKey *eddsa.PrivateKey, recipient, provider string) error
}

type UnreliableSpoolService struct {
	session *session.Session
}

func New(session *session.Session) *UnreliableSpoolService {
	return &UnreliableSpoolService{
		session: session,
	}
}

func (s *UnreliableSpoolService) submitCommand(cmd []byte, recipient, provider string) (*common.SpoolResponse, error) {
	mesgID, err := s.session.SendUnreliableMessage(recipient, provider, cmd)
	if err != nil {
		return nil, err
	}
	reply, err := s.session.WaitForReply(mesgID)
	if err != nil {
		return nil, err
	}
	spoolResponse, err := common.SpoolResponseFromBytes(reply)
	if err != nil {
		return nil, err
	}
	if strings.Compare(spoolResponse.Status, OKStatus) == 0 {
		return &spoolResponse, nil
	}

	return nil, fmt.Errorf("spool command failure: %s", spoolResponse.Status)
}

func (s *UnreliableSpoolService) CreateSpool(privKey *eddsa.PrivateKey, recipient, provider string) ([]byte, error) {
	cmd, err := common.CreateSpool(privKey)
	if err != nil {
		return nil, err
	}
	spoolResponse, err := s.submitCommand(cmd, recipient, provider)
	if err != nil {
		return nil, err
	}
	return spoolResponse.SpoolID, nil
}

func (s *UnreliableSpoolService) PurgeSpool(spoolID []byte, privKey *eddsa.PrivateKey, recipient, provider string) error {
	if len(spoolID) != common.SpoolIDSize {
		return errors.New("spoolID wrong size")
	}
	_spoolID := [common.SpoolIDSize]byte{}
	copy(_spoolID[:], spoolID)
	cmd, err := common.PurgeSpool(_spoolID, privKey)
	if err != nil {
		return err
	}
	_, err = s.submitCommand(cmd, recipient, provider)
	return err
}

func (s *UnreliableSpoolService) AppendToSpool(spoolID []byte, message []byte, recipient, provider string) error {
	if len(spoolID) != common.SpoolIDSize {
		return errors.New("spoolID wrong size")
	}
	_spoolID := [common.SpoolIDSize]byte{}
	copy(_spoolID[:], spoolID)
	cmd, err := common.AppendToSpool(_spoolID, message)
	if err != nil {
		return err
	}
	_, err = s.submitCommand(cmd, recipient, provider)
	return err
}

func (s *UnreliableSpoolService) ReadFromSpool(spoolID []byte, messageID uint32,
	privKey *eddsa.PrivateKey,
	recipient,
	provider string) (*common.SpoolResponse, error) {
	if len(spoolID) != common.SpoolIDSize {
		return nil, errors.New("spoolID wrong size")
	}
	_spoolID := [common.SpoolIDSize]byte{}
	copy(_spoolID[:], spoolID)
	cmd, err := common.ReadFromSpool(_spoolID, messageID, privKey)
	if err != nil {
		return nil, err
	}
	return s.submitCommand(cmd, recipient, provider)
}
