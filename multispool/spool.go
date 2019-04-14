// spool.go - remote spool operations
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

package multispool

import (
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/ugorji/go/codec"
)

const (
	SpoolIDSize   = 12
	SignatureSize = 64
	PublicKeySize = 32
	MessageIDSize = 4

	CreateSpoolCommand     = 0
	PurgeSpoolCommand      = 1
	AppendMessageCommand   = 2
	RetrieveMessageCommand = 3
)

var (
	cborHandle = new(codec.CborHandle)
)

type SpoolRequest struct {
	Command   byte
	SpoolID   []byte
	Signature []byte
	PublicKey []byte
	MessageID uint32
	Message   []byte
}

func SpoolRequestFromBytes(raw []byte) (SpoolRequest, error) {
	s := SpoolRequest{}
	dec := codec.NewDecoderBytes(raw, cborHandle)
	err := dec.Decode(&s)
	return s, err
}

func (s *SpoolRequest) Encode() ([]byte, error) {
	out := []byte{}
	enc := codec.NewEncoderBytes(&out, cborHandle)
	err := enc.Encode(s)
	return out, err
}

type SpoolResponse struct {
	SpoolID []byte
	Message []byte
	Status  string
}

func SpoolResponseFromBytes(raw []byte) (SpoolResponse, error) {
	s := SpoolResponse{}
	dec := codec.NewDecoderBytes(raw, cborHandle)
	err := dec.Decode(&s)
	return s, err
}

func (s *SpoolResponse) Encode() ([]byte, error) {
	out := []byte{}
	enc := codec.NewEncoderBytes(&out, cborHandle)
	err := enc.Encode(s)
	return out, err
}

func CreateSpool(privKey *eddsa.PrivateKey) ([]byte, error) {
	signature := privKey.Sign(privKey.PublicKey().Bytes())
	emtpySpoolID := [SpoolIDSize]byte{}
	emptyMessage := []byte{}
	s := SpoolRequest{
		Command:   CreateSpoolCommand,
		SpoolID:   emtpySpoolID[:],
		Signature: signature,
		PublicKey: privKey.PublicKey().Bytes(),
		MessageID: 0,
		Message:   emptyMessage,
	}
	return s.Encode()
}

func PurgeSpool(spoolID [SpoolIDSize]byte, privKey *eddsa.PrivateKey) ([]byte, error) {
	signature := privKey.Sign(privKey.PublicKey().Bytes())
	s := SpoolRequest{
		Command:   PurgeSpoolCommand,
		PublicKey: privKey.PublicKey().Bytes(),
		Signature: signature,
		SpoolID:   spoolID[:],
	}
	return s.Encode()
}

func AppendToSpool(spoolID [SpoolIDSize]byte, message []byte) ([]byte, error) {
	s := SpoolRequest{
		Command: AppendMessageCommand,
		SpoolID: spoolID[:],
		Message: message[:],
	}
	return s.Encode()
}

func ReadFromSpool(spoolID [SpoolIDSize]byte, messageID uint32, privKey *eddsa.PrivateKey) ([]byte, error) {
	signature := privKey.Sign(privKey.PublicKey().Bytes())
	s := SpoolRequest{
		Command:   RetrieveMessageCommand,
		PublicKey: privKey.PublicKey().Bytes(),
		Signature: signature,
		SpoolID:   spoolID[:],
		MessageID: messageID,
	}
	return s.Encode()
}
