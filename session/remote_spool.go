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
	"github.com/katzenpost/client/multispool"
	"github.com/katzenpost/core/crypto/eddsa"
)

// XXX work-in-progress
func (s *Session) SendCreateSpool(privKey *eddsa.PrivateKey, recipient, provider string) error {
	cmd, err := multispool.CreateSpool(privKey)
	if err != nil {
		return err
	}
	_, err = s.SendUnreliableQuery(recipient, provider, cmd)
	if err != nil {
		return err
	}
	return nil
}
