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
	"crypto/hmac"
	"encoding/binary"
	"errors"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/katzenpost/core/crypto/sign/ed25519sphincsplus"
)

const (
	// CertVersion is the certificate format version.
	CertVersion = 0
)

var (
	// ErrImpossibleDecode is an impossible decoding error.
	ErrImpossibleDecode = errors.New("impossible to decode")

	// ErrImpossibleEncode is an impossible encoding error.
	ErrImpossibleEncode = errors.New("impossible to encode")

	// ErrImpossibleOutOfMemory is an impossible out of memory error.
	ErrImpossibleOutOfMemory = errors.New("impossible out of memory failure")

	// ErrBadSignature indicates that the given signature does not sign the certificate.
	ErrBadSignature = errors.New("signature does not sign certificate")

	// ErrDuplicateSignature indicates that the given signature is already present in the certificate.
	ErrDuplicateSignature = errors.New("signature must not be duplicate")

	// ErrInvalidCertified indicates that the certified field is invalid
	ErrInvalidCertified = errors.New("invalid certified field of certificate")

	// ErrKeyTypeMismatch indicates that the given signer's key type is different than the signatures present already.
	ErrKeyTypeMismatch = errors.New("certificate key type mismatch")

	// ErrInvalidKeyType indicates that the given signer's key type is different than the signatures present already.
	ErrInvalidKeyType = errors.New("invalid certificate key type")

	// ErrVersionMismatch indicates that the given certificate is the wrong format version.
	ErrVersionMismatch = errors.New("certificate version mismatch")

	// ErrCertificateExpired indicates that the given certificate has expired.
	ErrCertificateExpired = errors.New("certificate expired")

	// ErrIdentitySignatureNotFound indicates that for the given signer identity there was no signature present in the certificate.
	ErrIdentitySignatureNotFound = errors.New("failure to find signature associated with the given identity")

	// ErrInvalidThreshold indicated the given threshold cannot be used.
	ErrInvalidThreshold = errors.New("threshold must be equal or less than the number of verifiers")

	// ErrThresholdNotMet indicates that there were not enough valid signatures to meet the threshold.
	ErrThresholdNotMet = errors.New("threshold failure")

	// Scheme is the signature scheme we are using throughout various components of the network.
	Scheme = ed25519sphincsplus.Scheme

	// Create reusable EncMode interface with immutable options, safe for concurrent use.
	ccbor cbor.EncMode
)

// Verifier is used to verify signatures.
type Verifier interface {
	// Verify verifies a signature.
	Verify(sig, msg []byte) bool

	// Sum256 returns the Blake2b 256-bit checksum of the key's raw bytes.
	Sum256() [32]byte
}

// Signer signs messages.
type Signer interface {
	// Sign signs the message and returns the signature.
	Sign(msg []byte) []byte

	// KeyType returns the key type string.
	KeyType() string
}

// Signature is a cryptographic signature
// which has an associated signer ID.
type Signature struct {
	// PublicKeySum256 is the 256 bit hash of the public key.
	PublicKeySum256 [32]byte

	// Payload is the actual signature value.
	Payload []byte
}

// Marshal serializes a Signature
func (s *Signature) Marshal() ([]byte, error) {
	return ccbor.Marshal(s)
}

// Unmarshal deserializes a Signature
func (s *Signature) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, s)
}

// Certificate structure for serializing certificates.
type Certificate struct {
	// Version is the certificate format version.
	Version uint32

	// Expiration is katzenpost epoch id of the expiration,
	// where if set to `epoch` then at `epoch-1` the
	// certificate is valid and at `epoch` or `epoch+n`
	// the certificate is not valid.
	Expiration uint64

	// KeyType indicates the type of key
	// that is certified by this certificate.
	KeyType string

	// Payload is the bulk of the data that is certified by
	// this certificate. The other signed elements can be found
	// in the certified() method below.
	Payload []byte

	// Signatures is a map PublicKeySum256 -> {PublicKeySum256, Payload}
	// where PublicKeySum256 is the signer's public key and Payload is
	// a signature over Certificate.message() (canonical encoding of
	// the previous fields of the Certificate)
	Signatures map[[32]byte]Signature
}

func Unmarshal(raw []byte) (*Certificate, error) {
	if raw == nil {
		return nil, errors.New("ERROR: Unmarshal received a nil byte blob.")
	}
	cert := new(Certificate)
	cert.Signatures = make(map[[32]byte]Signature)
	err := cbor.Unmarshal(raw, cert)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (c *Certificate) Marshal() ([]byte, error) {
	return ccbor.Marshal(c)
}

func (c *Certificate) certified() ([]byte, error) {
	message := new(bytes.Buffer)
	err := binary.Write(message, binary.LittleEndian, c.Version)
	if err != nil {
		return nil, ErrImpossibleOutOfMemory
	}
	err = binary.Write(message, binary.LittleEndian, c.Expiration)
	if err != nil {
		return nil, ErrImpossibleOutOfMemory
	}
	_, err = message.Write([]byte(c.KeyType))
	if err != nil {
		return nil, ErrImpossibleOutOfMemory
	}
	_, err = message.Write(c.Payload)
	if err != nil {
		return nil, ErrImpossibleOutOfMemory
	}
	return message.Bytes(), nil
}

func (c *Certificate) SanityCheck(currentEpoch uint64) error {
	if c.Version != CertVersion {
		return ErrVersionMismatch
	}
	if currentEpoch >= c.Expiration {
		return ErrCertificateExpired
	}
	if len(c.KeyType) == 0 {
		return ErrInvalidKeyType
	}
	if len(c.Payload) == 0 || c.Payload == nil {
		return ErrInvalidCertified
	}
	if c.Signatures == nil {
		// it seems cbor will faithfully unmarshal a nil map as nil,
		// so we need to correct that:
		c.Signatures = make(map[[32]byte]Signature)
	}
	return nil
}

// Sign uses the given Signer to create a certificate which
// certifies the given data.
func Sign(signer Signer, verifier Verifier, data []byte, expirationEpoch, currentEpoch uint64) ([]byte, error) {
	cert := Certificate{
		Version:    CertVersion,
		Expiration: expirationEpoch,
		KeyType:    signer.KeyType(),
		Payload:    data,
	}
	err := cert.SanityCheck(currentEpoch)
	if err != nil {
		return nil, err
	}
	mesg, err := cert.certified()
	if err != nil {
		return nil, err
	}
	cert.Signatures = make(map[[32]byte]Signature)
	cert.Signatures[verifier.Sum256()] = Signature{
		PublicKeySum256: verifier.Sum256(),
		Payload:         signer.Sign(mesg),
	}
	return cert.Marshal()
}

func GetPayload(rawCert []byte) ([]byte, error) {
	cert := new(Certificate)
	err := cbor.Unmarshal(rawCert, cert)
	if err != nil {
		return nil, ErrImpossibleDecode
	}
	return cert.Payload, nil
}

// GetCertified returns the certified data.
func GetCertificate(rawCert []byte) (*Certificate, error) {
	cert := new(Certificate)
	err := cbor.Unmarshal(rawCert, cert)
	if err != nil {
		return nil, ErrImpossibleDecode
	}
	return cert, nil
}

// GetSignatures returns all the signatures.
func GetSignatures(rawCert []byte) ([]Signature, error) {
	cert := new(Certificate)
	err := cbor.Unmarshal(rawCert, cert)
	if err != nil {
		return nil, ErrImpossibleDecode
	}
	s := make([]Signature, len(cert.Signatures))
	i := 0
	for _, v := range cert.Signatures {
		s[i] = v
		i++
	}
	return s, nil
}

// GetSignature returns a signature that signs the certificate
// if it matches with the given identity.
func GetSignature(identity []byte, rawCert []byte, currentEpoch uint64) (*Signature, error) {
	cert := new(Certificate)
	err := cbor.Unmarshal(rawCert, cert)
	if err != nil {
		return nil, ErrImpossibleDecode
	}
	err = cert.SanityCheck(currentEpoch)
	if err != nil {
		return nil, err
	}
	for _, s := range cert.Signatures {
		hash := s.PublicKeySum256
		if hmac.Equal(identity, hash[:]) {
			return &s, nil
		}
	}
	return nil, ErrIdentitySignatureNotFound
}

type byIdentity []Signature

func (d byIdentity) Len() int {
	return len(d)
}

func (d byIdentity) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func (d byIdentity) Less(i, j int) bool {
	hash1 := d[i].PublicKeySum256
	hash2 := d[j].PublicKeySum256
	return bytes.Compare(hash1[:], hash2[:]) < 0
}

// SignMulti uses the given signer to create a signature
// and appends it to the certificate and returns it.
func SignMulti(signer Signer, verifier Verifier, rawCert []byte, currentEpoch uint64) ([]byte, error) {
	// decode certificate
	cert := new(Certificate)
	err := cbor.Unmarshal(rawCert, cert)
	if err != nil {
		return nil, ErrImpossibleDecode
	}
	err = cert.SanityCheck(currentEpoch)
	if err != nil {
		return nil, err
	}
	if signer.KeyType() != cert.KeyType {
		return nil, ErrKeyTypeMismatch
	}

	// sign the certificate's message contents
	mesg, err := cert.certified()
	if err != nil {
		return nil, err
	}
	signature := Signature{
		PublicKeySum256: verifier.Sum256(),
		Payload:         signer.Sign(mesg),
	}

	cert.Signatures[signature.PublicKeySum256] = signature

	// serialize certificate
	out, err := cert.Marshal()
	if err != nil {
		return nil, ErrImpossibleEncode
	}
	return out, nil
}

// AddSignature adds the signature to the certificate if the verifier
// can verify the signature signs the certificate.
func AddSignature(verifier Verifier, signature Signature, rawCert []byte) ([]byte, error) {
	// decode certificate
	cert := new(Certificate)
	err := cbor.Unmarshal(rawCert, cert)
	if err != nil {
		return nil, ErrImpossibleDecode
	}

	// dedup
	for _, sig := range cert.Signatures {
		if hmac.Equal(sig.PublicKeySum256[:], signature.PublicKeySum256[:]) {
			return nil, ErrDuplicateSignature
		}
	}

	// sign the certificate's message contents
	mesg, err := cert.certified()
	if err != nil {
		return nil, err
	}

	if verifier.Verify(signature.Payload, mesg) {
		cert.Signatures[signature.PublicKeySum256] = signature
	} else {
		return nil, ErrBadSignature
	}
	// serialize certificate
	out, err := cert.Marshal()
	if err != nil {
		return nil, ErrImpossibleEncode
	}
	return out, nil
}

// Verify is used to verify one of the signatures attached to the certificate.
// It returns the certified data if the signature is valid.
func Verify(verifier Verifier, cert *Certificate, currentEpoch uint64) ([]byte, error) {
	err := cert.SanityCheck(currentEpoch)
	if err != nil {
		return nil, err
	}
	for _, sig := range cert.Signatures {
		hash := verifier.Sum256()
		if hmac.Equal(hash[:], sig.PublicKeySum256[:]) {
			mesg, err := cert.certified()
			if err != nil {
				return nil, err
			}
			if verifier.Verify(sig.Payload, mesg) {
				return cert.Payload, nil
			}
			return nil, ErrBadSignature
		}
	}
	return nil, ErrIdentitySignatureNotFound
}

// VerifyThreshold returns the certified data, the succeeded verifiers
// and the failed verifiers if at least a threshold number of verifiers
// can verify the certificate. Otherwise nil is returned along with an
// error.
func VerifyThreshold(verifiers []Verifier, threshold int, cert *Certificate, currentEpoch uint64) ([]byte, []Verifier, []Verifier, error) {
	if threshold > len(verifiers) {
		return nil, nil, nil, ErrInvalidThreshold
	}
	certified := []byte{}
	count := 0
	good := make(map[[32]byte]*Verifier)
	bad := []Verifier{}
	for i, verifier := range verifiers {
		c, err := Verify(verifier, cert, currentEpoch)
		if err != nil {
			bad = append(bad, verifier)
			continue
		}
		good[verifier.Sum256()] = &verifiers[i]
		certified = c
		count++
	}
	var good_out []Verifier
	for _, v := range good {
		good_out = append(good_out, *v)
	}
	if len(good) >= threshold {
		return certified, good_out, bad, nil
	}

	return nil, good_out, bad, ErrThresholdNotMet
}

func init() {
	var err error
	opts := cbor.CanonicalEncOptions()
	ccbor, err = opts.EncMode()
	if err != nil {
		panic(err)
	}
}
