// common.go - common code for cbor plugin system
// Copyright (C) 2021  David Stainton.
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

package cborplugin

import (
	"net"

	"encoding/binary"
	"github.com/fxamacker/cbor/v2"
)

type Plugin interface {
	OnRequest(Command) (Command, error)
}

type Command interface {
	MarshalCBOR() (data []byte, err error)
	UnmarshalCBOR(data []byte) error
}

type CommandBuilder interface {
	Build() Command
}

type Request struct {
	GetParameters bool
	Payload       []byte
}

func (r *Request) MarshalCBOR() (data []byte, err error) {
	return cbor.Marshal(r)
}

func (r *Request) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, r)
}

// Response is the response received after sending a Request to the plugin.
type Response struct {
	Payload []byte
}

func (r *Response) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, r)
}

func (r *Response) MarshalCBOR() (data []byte, err error) {
	return cbor.Marshal(r)
}

// Parameters is an optional mapping that plugins can publish, these get
// advertised to clients in the MixDescriptor.
// The output of GetParameters() ends up being published in a map
// associating with the service names to service parameters map.
// This information is part of the Mix Descriptor which is defined here:
// https://github.com/katzenpost/core/blob/master/pki/pki.go
type Parameters map[string]string

func (p *Parameters) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, p)
}

func (p *Parameters) MarshalCBOR() (data []byte, err error) {
	return cbor.Marshal(p)
}

func (p *Parameters) SetEndpoint(endpoint string) {
	map[string]string(*p)["endpoint"] = endpoint
}

func readCommand(conn net.Conn, command Command) error {
	rawLen := make([]byte, 2)
	_, err := conn.Read(rawLen)
	if err != nil {
		return err
	}
	commandLen := binary.BigEndian.Uint16(rawLen)

	rawCommand := make([]byte, commandLen)
	_, err = conn.Read(rawCommand)
	if err != nil {
		return err
	}
	err = command.UnmarshalCBOR(rawCommand)
	if err != nil {
		return err
	}

	return nil
}

func writeCommand(conn net.Conn, command Command) error {
	serialized, err := cbor.Marshal(command)
	if err != nil {
		return err
	}

	output := make([]byte, len(serialized)+2)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(serialized)))
	copy(output, tmp)
	copy(output[2:], serialized)
	_, err = conn.Write(output)
	if err != nil {
		return err
	}

	return nil
}
