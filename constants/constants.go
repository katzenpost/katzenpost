// constants.go - catshadow constants
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

package constants

import (
	ratchet "github.com/katzenpost/doubleratchet"
	"github.com/katzenpost/memspool/common"
)

const (
	// ReadInboxPoissonLambda is use to tune a poisson process for controlling
	// remote spool polling interval.
	ReadInboxPoissonLambda = 0.0001234

	// ReadInboxPoissonMax is the maximum remote spool polling interval.
	ReadInboxPoissonMax = 90000

	// DoubleRatchetPayloadLength is the length of the payload encrypted by the ratchet.
	DoubleRatchetPayloadLength = common.SpoolPayloadLength - ratchet.DoubleRatchetOverhead
)
