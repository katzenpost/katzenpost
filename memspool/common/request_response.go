// request_response.go - remote spool operations request and response types
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

package common

import (
	"errors"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/sign"
	eddsa "github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const (
	// SpoolIDSize is the size of a spool identity
	SpoolIDSize = 12

	// SignatureSize is the size of a spool command signature
	SignatureSize = 64

	// PublicKeySize is the size of a public key for verifying
	// spool command signatures.
	PublicKeySize = 32

	// MessageIDSize is the size of a message identity.
	MessageIDSize = 4

	// ResponsePadding is size of the padding of the spool service response.
	ResponsePadding = 171

	// QueryOverhead is the number of bytes overhead
	// from the spool command CBOR encoding.
	QueryOverhead = 171

	// CreateSpoolCommand is the identity of the create spool command.
	CreateSpoolCommand = 0

	// PurgeSpoolCommand is the identity of the purge spool command.
	PurgeSpoolCommand = 1

	// AppendMessageCommand is the identity of the append message command.
	AppendMessageCommand = 2

	// RetrieveMessageCommand is the identity of the retrieve message command.
	RetrieveMessageCommand = 3

	// SpoolServiceName is the canonical name of the memspool service.
	SpoolServiceName = "spool"

	// StatusOK is a status string indicating there was no error on the spool operation.
	StatusOK = "OK"
)

// SpoolRequest is the message sent to the spool server
type SpoolRequest struct {
	Command byte

	// SpoolID identities a spool on a particular Provider host.
	// This field must be SpoolIDSize bytes long.
	SpoolID   [SpoolIDSize]byte
	Signature []byte
	PublicKey []byte
	MessageID uint32
	Message   []byte
}

// Marshal implements cborplugin.Command
func (s *SpoolRequest) Marshal() ([]byte, error) {
	return cbor.Marshal(s)
}

// Unmarshal implements cborplugin.Command
func (s *SpoolRequest) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, s)
}

// SpoolResponse is the response message from the spool server
type SpoolResponse struct {
	SpoolID   [SpoolIDSize]byte
	MessageID uint32
	Message   []byte
	Status    string
}

// Marshal implements cborplugin.Command
func (s *SpoolResponse) Marshal() ([]byte, error) {
	return cbor.Marshal(s)
}

// Unmarshal implements cborplugin.Command
func (s *SpoolResponse) Unmarshal(b []byte) error {
	_, err := cbor.UnmarshalFirst(b, s)
	return err
}

func (s *SpoolResponse) IsOK() bool {
	return s.Status == StatusOK
}

func (s *SpoolResponse) StatusAsError() error {
	return errors.New(s.Status)
}

func CreateSpool(privKey sign.PrivateKey) ([]byte, error) {
	message, err := privKey.Public().(*eddsa.PublicKey).MarshalBinary()
	if err != nil {
		return nil, err
	}
	signature := privKey.Scheme().Sign(privKey, message, nil)
	emtpySpoolID := [SpoolIDSize]byte{}
	emptyMessage := []byte{}
	s := SpoolRequest{
		Command:   CreateSpoolCommand,
		SpoolID:   emtpySpoolID,
		Signature: signature,
		PublicKey: privKey.Public().(*eddsa.PublicKey).Bytes(),
		MessageID: 0,
		Message:   emptyMessage,
	}
	return s.Marshal()
}

func PurgeSpool(spoolID [SpoolIDSize]byte, privKey sign.PrivateKey) ([]byte, error) {
	message, err := privKey.Public().(sign.PublicKey).MarshalBinary()
	if err != nil {
		return nil, err
	}
	signature := privKey.Scheme().Sign(privKey, message, nil)
	pubkeyblob, err := privKey.Public().(sign.PublicKey).MarshalBinary()
	s := SpoolRequest{
		Command:   PurgeSpoolCommand,
		PublicKey: pubkeyblob,
		Signature: signature,
		SpoolID:   spoolID,
	}
	return s.Marshal()
}

func SpoolPayloadLength(geo *geo.Geometry) int {
	return (geo.UserForwardPayloadLength - 4) - QueryOverhead
}

func AppendToSpool(spoolID [SpoolIDSize]byte, message []byte, geo *geo.Geometry) ([]byte, error) {
	if len(message) > SpoolPayloadLength(geo) {
		return nil, errors.New("exceeds payload maximum")
	}
	s := SpoolRequest{
		Command: AppendMessageCommand,
		SpoolID: spoolID,
		Message: message[:],
	}
	return s.Marshal()
}

func ReadFromSpool(spoolID [SpoolIDSize]byte, messageID uint32, privKey sign.PrivateKey) ([]byte, error) {
	message, err := privKey.Public().(sign.PublicKey).MarshalBinary()
	if err != nil {
		return nil, err
	}
	signature := privKey.Scheme().Sign(privKey, message, nil)
	pubkey, err := privKey.Public().(sign.PublicKey).MarshalBinary()
	if err != nil {
		return nil, err
	}
	s := SpoolRequest{
		Command:   RetrieveMessageCommand,
		PublicKey: pubkey,
		Signature: signature,
		SpoolID:   spoolID,
		MessageID: messageID,
	}
	return s.Marshal()
}
