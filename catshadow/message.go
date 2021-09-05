// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// message.go - client message descriptor types
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
	"time"
)

type SentMessageDescriptor struct {
	// Nickname is the contact nickname to whom a message was sent.
	Nickname string

	// MessageID is the key in the conversation map referencing a specific message.
	MessageID MessageID
}

// Message encapsulates message that is sent or received.
type Message struct {
	Plaintext []byte
	Timestamp time.Time
	Outbound  bool
	Sent      bool
	Delivered bool
}

type Messages []*Message

// Len implements sort.Interface.
func (d Messages) Len() int {
	return len(d)
}

// Swap is part of sort.Interface.
func (d Messages) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

// Less is part of sort.Interface.
func (d Messages) Less(i, j int) bool {
	return d[i].Timestamp.Before(d[j].Timestamp)
}
