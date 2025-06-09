// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
)

const (
	SignatureSchemeName = "Ed25519"
)

var (
	// Create reusable EncMode interface with immutable options, safe for concurrent use.
	ccbor cbor.EncMode
)

// Geometry describes the geometry of the Pigeonhole Protocol messages.
type Geometry struct {

	// CourierEnvelopeLength is the length of the CourierEnvelope message.
	CourierEnvelopeLength int

	// CourierEnvelopeReplyLength is the length of the CourierEnvelopeReply message.
	CourierEnvelopeReplyLength int

	// NikeName is the name of the NIKE scheme used by our MKEM scheme to encrypt
	// the CourierEnvelope and CourierEnvelopeReply messages.
	NIKEName string

	// SignatureSchemeName is the name of the signature scheme used
	// by BACAP to sign payloads.
	SignatureSchemeName string

	// UserForwardPayloadLength is the size of the usable payload.
	UserForwardPayloadLength int
}

// Validate returns an error if one of it's validation checks fails.
func (g *Geometry) Validate() error {
	if g == nil {
		return errors.New("geometry reference is nil")
	}
	if g.NIKEName != "" {
		mynike := schemes.ByName(g.NIKEName)
		if mynike == nil {
			return fmt.Errorf("geometry has invalid NIKE Scheme %s", g.NIKEName)
		}
	} else {
		return errors.New("geometry NIKEName is not set")
	}
	if g.SignatureSchemeName != SignatureSchemeName {
		return errors.New("geometry SignatureSchemeName must be set to Ed25519")
	}
	if g.UserForwardPayloadLength == 0 {
		return errors.New("geometry UserForwardPayloadLength is not set")
	}
	return nil
}

func (g *Geometry) NIKEScheme() nike.Scheme {
	s := schemes.ByName(g.NIKEName)
	if s == nil {
		panic("failed to get a scheme")
	}
	return s
}

func (g *Geometry) SignatureScheme() sign.Scheme {
	s := signSchemes.ByName(g.SignatureSchemeName)
	if s == nil {
		panic("failed to get a scheme")
	}
	return s
}

func (g *Geometry) String() string {
	var b strings.Builder
	b.WriteString("pigeonhole_geometry:\n")
	b.WriteString(fmt.Sprintf("CourierEnvelopeLength: %d\n", g.CourierEnvelopeLength))
	b.WriteString(fmt.Sprintf("CourierEnvelopeReplyLength: %d\n", g.CourierEnvelopeReplyLength))
	b.WriteString(fmt.Sprintf("NIKEName: %s\n", g.NIKEName))
	b.WriteString(fmt.Sprintf("SignatureSchemeName: %s\n", g.SignatureSchemeName))
	b.WriteString(fmt.Sprintf("UserForwardPayloadLength: %d\n", g.UserForwardPayloadLength))
	return b.String()
}

type Config struct {
	PigeonholeGeometry *Geometry
}

func (g *Geometry) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	encoder := toml.NewEncoder(buf)
	config := &Config{
		PigeonholeGeometry: g,
	}
	err := encoder.Encode(config)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (g *Geometry) Display() string {
	blob, err := g.Marshal()
	if err != nil {
		panic(err)
	}
	return string(blob)
}

func (g *Geometry) bytes() []byte {
	blob, err := ccbor.Marshal(g)
	if err != nil {
		panic(err)
	}
	return blob
}

func (g *Geometry) Hash() []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, err = h.Write(g.bytes())
	if err != nil {
		panic(err)
	}
	return h.Sum(nil)
}

func init() {
	var err error
	opts := cbor.CanonicalEncOptions()
	ccbor, err = opts.EncMode()
	if err != nil {
		panic(err)
	}
}
