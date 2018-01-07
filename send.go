// send.go - Send related routines.
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

package minclient

import (
	"fmt"
	"time"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/sphinx/commands"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/minclient/internal/path"
)

// SendUnreliableCiphertext sends the ciphertext b to the recipient/provider,
// in an unreliable manner.  No notification of the packet being received will
// be generated by the recipient's provider.
func (c *Client) SendUnreliableCiphertext(recipient, provider string, b []byte) error {
	if len(recipient) > sConstants.RecipientIDLength {
		return fmt.Errorf("minclient: invalid recipient: '%v'", recipient)
	}
	if len(b) != constants.UserForwardPayloadLength {
		return fmt.Errorf("minclient: invalid ciphertext size: %v", len(b))
	}

	// Wrap the ciphertext in a BlockSphinxCiphertext.
	payload := make([]byte, 2+sphinx.SURBLength, 2+sphinx.SURBLength+len(b))
	payload = append(payload, b...)

	for {
		unixTime := c.pki.skewedUnixTime()
		_, _, budget := epochtime.FromUnix(unixTime)
		start := time.Now()

		// Select the forward path.
		now := time.Unix(unixTime, 0)
		pktPath, then, err := c.makePath(recipient, provider, nil, now, true)
		if err != nil {
			return err
		}

		// If the path selection process ends up straddling an epoch
		// transition, then redo the path selection.
		if time.Since(start) > budget {
			continue
		}

		// It is possible, but unlikely that a series of delays exceeding
		// the PKI publication imposted limitations will be selected.  When
		// that happens, the path selection must be redone.
		if then.Sub(now) < epochtime.Period*2 {
			pkt, err := sphinx.NewPacket(rand.Reader, pktPath, payload)
			if err != nil {
				return err
			}

			return c.conn.sendPacket(pkt)
		}
	}
}

// SendCiphertext sends the ciphertext b to the recipient/provider, with a
// SURB identified by surbID, and returns the SURB decryption key and total
// round trip delay.
func (c *Client) SendCiphertext(recipient, provider string, surbID *[sConstants.SURBIDLength]byte, b []byte) ([]byte, time.Duration, error) {
	if len(recipient) > sConstants.RecipientIDLength {
		return nil, 0, fmt.Errorf("minclient: invalid recipient: '%v'", recipient)
	}
	if len(b) != constants.UserForwardPayloadLength {
		return nil, 0, fmt.Errorf("minclient: invalid ciphertext size: %v", len(b))
	}

	for {
		unixTime := c.pki.skewedUnixTime()
		_, _, budget := epochtime.FromUnix(unixTime)
		start := time.Now()

		now := time.Unix(unixTime, 0)

		fwdPath, then, err := c.makePath(recipient, provider, surbID, now, true)
		if err != nil {
			return nil, 0, err
		}

		revPath, then, err := c.makePath(c.cfg.User, provider, surbID, then, false)
		if err != nil {
			return nil, 0, err
		}

		if time.Since(start) > budget {
			continue
		}

		if then.Sub(now) < epochtime.Period*2 {
			payload := make([]byte, 2, 2+sphinx.SURBLength+len(b))
			payload[0] = 1 // Packet has a SURB.
			surb, k, err := sphinx.NewSURB(rand.Reader, revPath)
			if err != nil {
				return nil, 0, err
			}
			payload = append(payload, surb...)
			payload = append(payload, b...)

			pkt, err := sphinx.NewPacket(rand.Reader, fwdPath, payload)
			if err != nil {
				return nil, 0, err
			}

			err = c.conn.sendPacket(pkt)
			return k, then.Sub(now), err
		}
	}
}

func (c *Client) makePath(recipient, provider string, surbID *[sConstants.SURBIDLength]byte, baseTime time.Time, isForward bool) ([]*sphinx.PathHop, time.Time, error) {
	srcProvider, dstProvider := c.cfg.Provider, provider
	if !isForward {
		srcProvider, dstProvider = dstProvider, srcProvider
	}

	// Get the current PKI document.
	doc := c.CurrentDocument()
	if doc == nil {
		return nil, time.Time{}, fmt.Errorf("minclient: no PKI document for current epoch")
	}

	var then time.Time
	var pktPath []*sphinx.PathHop
selectLoop:
	for {
		// Generate a randomized path.
		descs, err := path.New(c.rng, doc, srcProvider, dstProvider)
		if err != nil {
			return nil, time.Time{}, err
		}

		then = baseTime
		pktPath = make([]*sphinx.PathHop, 0, len(descs))
		for idx, desc := range descs {
			// The reverse path needs to omit the provider that will use the
			// SURB, since the SURB doesn't go all the way to the recipient's
			// client.
			if !isForward && idx == 0 {
				continue
			}

			h := &sphinx.PathHop{}
			copy(h.ID[:], desc.IdentityKey.Bytes())
			epoch, _, _ := epochtime.FromUnix(then.Unix())
			if k, ok := desc.MixKeys[epoch]; !ok {
				c.log.Debugf("Hop[%v]: Node %v missing mixkey for epoch %v", idx, desc.IdentityKey, epoch)
				continue selectLoop
			} else {
				h.PublicKey = k
			}

			// All non-terminal hops, and the terminal forward hop iff the
			// packet has a SURB attached have a delay.
			delay := uint64(0)
			if idx != len(descs)-1 || (surbID != nil && isForward) {
				delay = uint64(rand.Exp(c.rng, doc.Lambda))
				if doc.MaxDelay > 0 && delay > doc.MaxDelay {
					delay = doc.MaxDelay
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
				copy(recipCmd.ID[:], []byte(recipient))
				h.Commands = append(h.Commands, recipCmd)

				if surbID != nil && !isForward {
					surbCmd := &commands.SURBReply{}
					copy(surbCmd.ID[:], surbID[:])
					h.Commands = append(h.Commands, surbCmd)
				}
			}

			c.log.Debugf("Hop[%v]: '%v' - %d ms.", idx, desc.Name, delay)
			pktPath = append(pktPath, h)
		}

		return pktPath, then, nil
	}
}
