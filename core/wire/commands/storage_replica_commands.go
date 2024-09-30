// SPDX-FileCopyrightText: Copyright (C) 2024  David Anthony Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package commands

import ()

type ReplicaMessage struct {
	SenderEPubKey []byte
	DEK           *[32]byte
	Ciphertext    []byte
}
