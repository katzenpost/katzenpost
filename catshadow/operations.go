// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// operations.go - catshadow operations
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

package catshadow

import (
	"context"
	"time"

	"github.com/katzenpost/katzenpost/memspool/client"
)

type opNop struct {
}

type opOnline struct {
	context context.Context
	responseChan chan error
}

type opOffline struct {
	responseChan chan error
}

type opCreateSpool struct {
	provider     string
	responseChan chan error
}

type opUpdateSpool struct {
	descriptor   *client.SpoolReadDescriptor
	responseChan chan error
}

type opAddContact struct {
	name         string
	sharedSecret []byte
}

type opRemoveContact struct {
	name         string
	responseChan chan error
}

type opRenameContact struct {
	oldname      string
	newname      string
	responseChan chan error
}

type opGetExpiration struct {
	name         string
	responseChan chan interface{}
}

type opChangeExpiration struct {
	name         string
	expiration   time.Duration
	responseChan chan error
}

type opSendMessage struct {
	id      MessageID
	name    string
	payload []byte
}

type opGetContacts struct {
	responseChan chan map[string]*Contact
}

type opGetConversation struct {
	name         string
	responseChan chan Messages
}

type opRestartSending struct {
	contact *Contact
}

type opWipeConversation struct {
	name         string
	responseChan chan error
}

type opGetPKIDocument struct {
	responseChan chan interface{}
}

type opGetSpoolProviders struct {
	responseChan chan interface{}
}

type opSpoolWriteDescriptor struct {
	responseChan chan *client.SpoolWriteDescriptor
}
