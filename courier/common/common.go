// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	cbor "github.com/fxamacker/cbor/v2"
)

type CourierMessage struct {
	SenderEPubKey [2][]byte
	Replicas      [2]uint8
	DEK           [2]*[32]byte
	Ciphertext    []byte
}

func (c *CourierMessage) Marshal() []byte {
	blob, err := cbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

func CourierMessageFromBytes(b []byte) (*CourierMessage, error) {
	c := &CourierMessage{}
	err := cbor.Unmarshal(b, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}
