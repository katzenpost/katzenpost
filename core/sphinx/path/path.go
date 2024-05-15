// path.go - Path selection routines.
// Copyright (C) 2017, 2018  Yawning Angel.
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

// Package path provides routines for path selection.
package path

import (
	"errors"
	"fmt"
	mRand "math/rand"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const maxAttempts = 3

var errMaxAttempts = errors.New("path: max path selection attempts exceeded")

// PathHop describes a hop that a Sphinx Packet will traverse, along with
// all of the per-hop Commands (excluding NextNodeHop).
type PathHop struct {
	ID            [constants.NodeIDLength]byte
	NIKEPublicKey nike.PublicKey
	KEMPublicKey  kem.PublicKey
	Commands      []commands.RoutingCommand
}

// New creates a new path suitable for use in creating a Sphinx packet with the
// specified parameters.
//
// Note: Forward packets originating from a client have slightly different
// path requirements than internally sourced packets or response packets as it
// includes the 0th hop.
func New(rng *mRand.Rand,
	sphinxGeometry *geo.Geometry,
	doc *pki.Document,
	recipient []byte,
	src, dst *pki.MixDescriptor,
	surbID *[constants.SURBIDLength]byte,
	baseTime time.Time,
	isFromClient,
	isForward bool) ([]*PathHop, time.Time, error) {

	var then time.Time
	var path []*PathHop
selectLoop:
	for attempts := 0; attempts < maxAttempts; attempts++ {
		descs, err := selectHops(rng, doc, src, dst, isFromClient, isForward)
		if err != nil {
			return nil, time.Time{}, err
		}

		then = baseTime
		path = make([]*PathHop, 0, len(descs))
		for idx, desc := range descs {

			h := &PathHop{}
			idHash := hash.Sum256(desc.IdentityKey)
			copy(h.ID[:], idHash[:])
			epoch, _, _ := epochtime.FromUnix(then.Unix())
			if _, ok := desc.MixKeys[epoch]; !ok {
				continue selectLoop
			} else {
				if sphinxGeometry.NIKEName == "" {
					h.KEMPublicKey, err = desc.UnmarshalMixKeyAsKEM(epoch, sphinxGeometry)
					if err != nil {
						return nil, time.Time{}, err
					}
				} else {
					h.NIKEPublicKey, err = desc.UnmarshalMixKeyAsNike(epoch, sphinxGeometry)
					if err != nil {
						return nil, time.Time{}, err
					}
				}

			}

			// All non-terminal hops, and the terminal forward hop iff the
			// packet has a SURB attached have a delay.
			var delay uint64
			if idx != len(descs)-1 || (surbID != nil && isForward) {
				delay = uint64(rand.Exp(rng, doc.Mu)) + 1
				if doc.MuMaxDelay > 0 && delay > doc.MuMaxDelay {
					delay = doc.MuMaxDelay
				}
				then = then.Add(time.Duration(delay) * time.Millisecond)
				delayCmd := &commands.NodeDelay{
					Delay: uint32(delay),
				}
				h.Commands = append(h.Commands, delayCmd)
			}

			// The terminal hop wil have a Recipient, and potentially a
			// SURBReply.
			if idx == len(descs)-1 {
				recipCmd := &commands.Recipient{}
				copy(recipCmd.ID[:], recipient)
				h.Commands = append(h.Commands, recipCmd)

				if surbID != nil && !isForward {
					surbCmd := &commands.SURBReply{}
					copy(surbCmd.ID[:], surbID[:])
					h.Commands = append(h.Commands, surbCmd)
				}
			}

			path = append(path, h)
		}

		return path, then, nil
	}

	return nil, time.Time{}, errMaxAttempts
}

func selectHops(rng *mRand.Rand, doc *pki.Document, src, dst *pki.MixDescriptor, isFromClient, isForward bool) ([]*pki.MixDescriptor, error) {
	var hops []*pki.MixDescriptor

	var startLayer, nHops int
	idHash := hash.Sum256(src.IdentityKey)
	srcLayer, err := doc.GetMixLayer(&idHash)
	if err != nil {
		return nil, err
	}
	idHash = hash.Sum256(dst.IdentityKey)
	dstLayer, err := doc.GetMixLayer(&idHash)
	if err != nil {
		return nil, err
	}
	if isForward {
		if !dst.IsServiceNode {
			return nil, fmt.Errorf("path: invalid destination (non service node): %x", hash.Sum256(dst.IdentityKey))
		}
		if isFromClient {
			// Client packets must span provider to provider.
			if !src.IsGatewayNode {
				return nil, fmt.Errorf("path: invalid source from client (non gateway node): %x", hash.Sum256(src.IdentityKey))
			}
			nHops = len(doc.Topology) + 2
		} else {
			switch int(srcLayer) {
			case pki.LayerGateway:
				startLayer = 0
			case pki.LayerService:
				startLayer = 0
			case len(doc.Topology) - 1:
				return []*pki.MixDescriptor{dst}, nil
			default:
				startLayer = int(srcLayer) + 1
			}
			nHops = len(doc.Topology) - startLayer
		}
	} else {
		if srcLayer != pki.LayerService {
			return nil, fmt.Errorf("path: invalid source layer: %v", srcLayer)
		}

		switch int(dstLayer) {
		case pki.LayerGateway:
			nHops = len(doc.Topology) + 1
		case pki.LayerService:
			nHops = len(doc.Topology) + 1
		case 0:
			return []*pki.MixDescriptor{dst}, nil
		default:
			nHops = int(dstLayer) + 1
		}
	}

	hops = make([]*pki.MixDescriptor, 0, nHops)
	if isForward && isFromClient {
		hops = append(hops, src)
	}
	for i, nodes := range doc.Topology[startLayer:] {
		if i == int(dstLayer) {
			break
		}
		if len(nodes) == 0 {
			return nil, fmt.Errorf("path: layer %v has no nodes", i)
		}
		hops = append(hops, nodes[rng.Intn(len(nodes))])
	}
	hops = append(hops, dst)

	return hops, nil
}

// ToString returns a slice of strings representing the "useful" component of
// each PathHop, suitable for debugging.
func ToString(doc *pki.Document, p []*PathHop) ([]string, error) {
	s := make([]string, 0, len(p))
	for idx, v := range p {
		desc, err := doc.GetNodeByKeyHash(&v.ID)
		if err != nil {
			return nil, err
		}

		var delay uint32
		for _, cmd := range v.Commands {
			if delayCmd, ok := cmd.(*commands.NodeDelay); ok {
				delay = delayCmd.Delay
				break
			}
		}
		s = append(s, fmt.Sprintf("Hop[%v] '%v' - %d ms", idx, desc.Name, delay))
	}
	return s, nil
}
