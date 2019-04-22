// methods copied and modified from agl's pond client source code

package catshadow

import (
	"encoding/binary"
	"github.com/katzenpost/core/crypto/rand"
)

func (c *Client) randId() uint64 {
	var idBytes [8]byte
	for {
		_, err := rand.Reader.Read(idBytes[:])
		if err != nil {
			panic(err)
		}
		n := binary.LittleEndian.Uint64(idBytes[:])
		if n == 0 {
			continue
		}
		if _, ok := c.contacts[n]; ok {
			continue
		}
		return n
	}
	panic("unreachable")
}
