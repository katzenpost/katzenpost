// common.go - code that is common to the PANDA client and server
// Copyright (C) 2018  David Stainton
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
)

const (
	PandaCapability = "panda"
	PandaVersion    = 0

	PandaStatusReceived1            = 0
	PandaStatusReceived2            = 1
	PandaStatusSyntaxError          = 2
	PandaStatusTagContendedError    = 3
	PandaStatusRequestRecordedError = 4
	PandaStatusStorageError         = 5

	PandaTagLength = 32
)

var ErrNoSuchPandaTag = errors.New("Error: no such PANDA tag")

type PandaRequest struct {
	Version int
	Tag     string
	Message string
}

type PandaResponse struct {
	Version    int
	StatusCode int
	Message    string
}
