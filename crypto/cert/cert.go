// cert.go - Cryptographic certificate library.
// Copyright (C) 2018  David Stainton.
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

// Package cert provides a cryptographic certicate library.
package cert

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"time"

	"github.com/ugorji/go/codec"
)

const (
	// CertVersion is the certificate format version.
	CertVersion = 0
)

var cborHandle *codec.CborHandle

// Verifier is used to verify signatures.
type Verifier interface {
	// Verify verifies a signature.
	Verify(sig, msg []byte) bool

	// Identity returns the Verifier identity.
	Identity() []byte
}

// Signer signs messages.
type Signer interface {
	// Sign signs the message and returns the signature.
	Sign(msg []byte) []byte

	// Identity returns the Signer identity.
	Identity() []byte

	// KeyType returns the key type string.
	KeyType() string
}

// Signature is a cryptographic signature
// which has an associated signer ID.
type Signature struct {
	// Identity is the identity of the signer.
	Identity []byte
	// Payload is the actual signature value.
	Payload []byte
}

// certificate structure for serializing certificates.
type certificate struct {
	// Version is the certificate format version.
	Version uint32

	// Expiration is seconds since Unix epoch.
	Expiration int64

	// KeyType indicates the type of key
	// that is certified by this certificate.
	KeyType string

	// Certified is the data that is certified by
	// this certificate.
	Certified []byte

	// Signatures are the signature of the certificate.
	Signatures []Signature
}

func (c *certificate) message() ([]byte, error) {
	message := new(bytes.Buffer)
	err := binary.Write(message, binary.LittleEndian, c.Version)
	if err != nil {
		return nil, err
	}
	err = binary.Write(message, binary.LittleEndian, c.Expiration)
	if err != nil {
		return nil, err
	}
	_, err = message.Write([]byte(c.KeyType))
	if err != nil {
		return nil, err
	}
	_, err = message.Write([]byte(c.Certified))
	return message.Bytes(), err
}

// Sign uses the given Signer to create a certificate which
// certifies the given data.
func Sign(signer Signer, data []byte, expiration int64) ([]byte, error) {
	cert := certificate{
		Version:    CertVersion,
		Expiration: expiration,
		KeyType:    signer.KeyType(),
		Certified:  data,
	}
	mesg, err := cert.message()
	if err != nil {
		return nil, err
	}
	cert.Signatures = []Signature{
		Signature{
			Identity: signer.Identity(),
			Payload:  signer.Sign(mesg),
		},
	}
	out := []byte{}
	enc := codec.NewEncoderBytes(&out, cborHandle)
	err = enc.Encode(&cert)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetCertified returns the certified data.
func GetCertified(rawCert []byte) ([]byte, error) {
	cert := certificate{}
	dec := codec.NewDecoderBytes(rawCert, cborHandle)
	err := dec.Decode(&cert)
	if err != nil {
		return nil, err
	}
	return cert.Certified, nil
}

// GetSignatures returns all the signatures.
func GetSignatures(rawCert []byte) ([]Signature, error) {
	cert := certificate{}
	dec := codec.NewDecoderBytes(rawCert, cborHandle)
	err := dec.Decode(&cert)
	if err != nil {
		return nil, err
	}
	return cert.Signatures, nil
}

// GetSignature returns a signature that signs the certificate
// if it matches with the given identity.
func GetSignature(identity []byte, rawCert []byte) (*Signature, error) {
	cert := certificate{}
	dec := codec.NewDecoderBytes(rawCert, cborHandle)
	err := dec.Decode(&cert)
	if err != nil {
		return nil, err
	}
	for _, s := range cert.Signatures {
		if bytes.Equal(identity, s.Identity) {
			return &s, nil
		}
	}
	return nil, errors.New("signature not found")
}

type byIdentity []Signature

func (d byIdentity) Len() int {
	return len(d)
}

func (d byIdentity) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func (d byIdentity) Less(i, j int) bool {
	return bytes.Compare(d[i].Identity, d[j].Identity) < 0
}

// SignMulti uses the given signer to create a signature
// and appends it to the certificate and returns it.
func SignMulti(signer Signer, rawCert []byte) ([]byte, error) {
	// decode certificate
	cert := new(certificate)
	dec := codec.NewDecoderBytes(rawCert, cborHandle)
	err := dec.Decode(cert)
	if err != nil {
		return nil, err
	}
	if signer.KeyType() != cert.KeyType {
		return nil, errors.New("certificate key type mismatch")
	}

	// sign the certificate's message contents
	mesg, err := cert.message()
	if err != nil {
		return nil, err
	}
	signature := Signature{
		Identity: signer.Identity(),
		Payload:  signer.Sign(mesg),
	}

	// dedup
	for _, sig := range cert.Signatures {
		if bytes.Equal(sig.Identity, signature.Identity) || bytes.Equal(sig.Payload, signature.Payload) {
			return nil, errors.New("signature must not be duplicate")
		}
	}

	cert.Signatures = append(cert.Signatures, signature)
	sort.Sort(byIdentity(cert.Signatures))

	// serialize certificate
	out := []byte{}
	enc := codec.NewEncoderBytes(&out, cborHandle)
	err = enc.Encode(&cert)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AddSignature adds the signature to the certificate if the verifier
// can verify the signature signs the certificate.
func AddSignature(verifier Verifier, signature Signature, rawCert []byte) ([]byte, error) {
	// decode certificate
	cert := new(certificate)
	dec := codec.NewDecoderBytes(rawCert, cborHandle)
	err := dec.Decode(cert)
	if err != nil {
		return nil, err
	}

	// dedup
	for _, sig := range cert.Signatures {
		if bytes.Equal(sig.Identity, signature.Identity) || bytes.Equal(sig.Payload, signature.Payload) {
			return nil, errors.New("signature must not be duplicate")
		}
	}

	// sign the certificate's message contents
	mesg, err := cert.message()
	if err != nil {
		return nil, err
	}
	if verifier.Verify(signature.Payload, mesg) {
		cert.Signatures = append(cert.Signatures, signature)
		sort.Sort(byIdentity(cert.Signatures))
	}
	// serialize certificate
	out := []byte{}
	enc := codec.NewEncoderBytes(&out, cborHandle)
	err = enc.Encode(&cert)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Verify is used to verify one of the signatures attached to the certificate.
// It returns the certified data if the signature is valid.
func Verify(verifier Verifier, rawCert []byte) ([]byte, error) {
	cert := new(certificate)
	enc := codec.NewDecoderBytes(rawCert, cborHandle)
	err := enc.Decode(cert)
	if err != nil {
		return nil, err
	}
	if time.Unix(cert.Expiration, 0).Before(time.Now()) {
		return nil, errors.New("certificate expired")
	}
	for _, sig := range cert.Signatures {
		if bytes.Equal(verifier.Identity(), sig.Identity) {
			mesg, err := cert.message()
			if err != nil {
				return nil, err
			}
			if verifier.Verify(sig.Payload, mesg) {
				return cert.Certified, nil
			}
			return nil, nil
		}
	}
	return nil, errors.New("failure to find signature associated with the given identity")
}

// VerifyAll returns the certified data if all of the given verifiers
// can verify the certificate. Otherwise nil is returned along with an error.
func VerifyAll(verifiers []Verifier, rawCert []byte) ([]byte, error) {
	var err error
	certified := []byte{}
	for _, verifier := range verifiers {
		certified, err = Verify(verifier, rawCert)
		if err != nil {
			return nil, err
		}
	}
	return certified, nil
}

// VerifyThreshold returns the certified data, the succeeded verifiers
// and the failed verifiers if at least a threshold number of verifiers
// can verify the certificate. Otherwise nil is returned along with an
// error.
func VerifyThreshold(verifiers []Verifier, threshold int, rawCert []byte) ([]byte, []Verifier, []Verifier, error) {
	if threshold > len(verifiers) {
		return nil, nil, nil, errors.New("threshold must be equal or less than the number of verifiers")
	}
	certified := []byte{}
	count := 0
	good := []Verifier{}
	bad := []Verifier{}
	for _, verifier := range verifiers {
		c, err := Verify(verifier, rawCert)
		if err != nil {
			bad = append(bad, verifier)
			continue
		}
		good = append(good, verifier)
		certified = c
		count++
	}
	if count >= threshold {
		return certified, good, bad, nil
	}
	return nil, good, bad, errors.New("threshold failure")
}

func init() {
	cborHandle = new(codec.CborHandle)
	cborHandle.Canonical = true
}
