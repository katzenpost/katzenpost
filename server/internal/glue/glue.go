// glue.go - Katzenpost server internal glue.
// Copyright (C) 2017  Yawning Angel.
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

// Package glue implements the glue structure that ties all the internal
// subpackages together.
package glue

import (
	"github.com/katzenpost/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/mixkey"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
	"github.com/katzenpost/katzenpost/server/spool"
	"github.com/katzenpost/katzenpost/server/userdb"
)

// Glue is the structure that binds the internal components together.
type Glue interface {
	Config() *config.Config
	LogBackend() *log.Backend
	IdentityKey() sign.PrivateKey
	IdentityPublicKey() sign.PublicKey
	LinkKey() wire.PrivateKey

	Management() *thwack.Server
	MixKeys() MixKeys
	PKI() PKI
	Provider() Provider
	Scheduler() Scheduler
	Connector() Connector
	Listeners() []Listener
	Decoy() Decoy

	ReshadowCryptoWorkers()
}

type MixKeys interface {
	Halt()
	Generate(uint64) (bool, error)
	Prune() bool
	Get(uint64) (*ecdh.PublicKey, bool)
	Shadow(map[uint64]*mixkey.MixKey)
}

type PKI interface {
	Halt()
	StartWorker()
	OutgoingDestinations() map[[constants.NodeIDLength]byte]*pki.MixDescriptor
	AuthenticateConnection(*wire.PeerCredentials, bool) (*pki.MixDescriptor, bool, bool)
	GetRawConsensus(uint64) ([]byte, error)
}

type Provider interface {
	Halt()
	UserDB() userdb.UserDB
	Spool() spool.Spool
	AuthenticateClient(*wire.PeerCredentials) bool
	OnPacket(*packet.Packet)
	KaetzchenForPKI() (map[string]map[string]interface{}, error)
}

type Scheduler interface {
	Halt()
	OnNewMixMaxDelay(uint64)
	OnPacket(*packet.Packet)
}

type Connector interface {
	Halt()
	DispatchPacket(*packet.Packet)
	IsValidForwardDest(*[constants.NodeIDLength]byte) bool
	ForceUpdate()
}

type Listener interface {
	Halt()
	CloseOldConns(interface{}) error
	GetConnIdentities() (map[[constants.RecipientIDLength]byte]interface{}, error)
	OnNewSendRatePerMinute(uint64)
	OnNewSendBurst(uint64)
}

type Decoy interface {
	Halt()
	OnNewDocument(*pkicache.Entry)
	OnPacket(*packet.Packet)
}
