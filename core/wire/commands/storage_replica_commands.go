// SPDX-FileCopyrightText: Copyright (C) 2024  David Anthony Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/binary"
	"errors"

	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
)

type WriteRequest struct {
	SenderEPubKey []byte
	DEK           *[32]byte
	Ciphertext    []byte
}

type WriteRequestReply struct {
	IsSuccess uint8
}

type ReadRequest struct {
	SenderEPubKey []byte
	DEK           *[32]byte
	Ciphertext    []byte
}

type ReadRequestReply struct {
	ID        *[32]byte
	Payload   []byte
	Signature []byte
}
