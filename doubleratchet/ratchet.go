// Package ratchet originally written by AGL to implement the axolotl ratchet
// (designed by Trevor Perrin) for the Pond messaging system but then
// modified for a Katzenpost decryption mix network messaging system.
// Improvements herein made by Masala, Sofia Celli and David Stainton.
// David's latest changes turn the ratchet into a computationally expensive
// PQ hybrid ratchet wherein there's an ECDH and a CSIDH ratchet which
// both progress together. Both of these ratchets feed their computed
// shared secrets into the KDF ratchet via the root KDF chain. More clever
// designs and feedback encouraged.
package ratchet

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"

	"github.com/awnumar/memguard"
	"github.com/fxamacker/cbor/v2"
	"github.com/henrydcase/nobs/dh/csidh"
	"github.com/katzenpost/katzenpost/doubleratchet/utils"
)

var (
	ErrDuplicateOrDelayed                     = errors.New("Ratchet: duplicate message or message delayed longer than tolerance")
	ErrHandshakeAlreadyComplete               = errors.New("Ratchet: handshake already complete")
	ErrCannotDecrypt                          = errors.New("Ratchet: cannot decrypt")
	ErrIncorrectHeaderSize                    = errors.New("Ratchet: incorrect header size")
	ErrSerialisedKeyLength                    = errors.New("Ratchet: bad serialised key length")
	ErrNextEncryptedMessageWithoutRatchetFlag = errors.New("Ratchet: received message encrypted to next header key without ratchet flag set")
	ErrOldFormKeyExchange                     = errors.New("Ratchet: peer using old-form key exchange")
	ErrCorruptMessage                         = errors.New("Ratchet: corrupt message")
	ErrMessageExceedsReorderingLimit          = errors.New("Ratchet: message exceeds reordering limit")
	ErrEchoedDHValues                         = errors.New("Ratchet: peer echoed our own DH values back")
	ErrInvalidSignatureLength                 = errors.New("Ratchet: invalid signature length")
	ErrRatchetHeaderTooSmall                  = errors.New("Ratchet: header too small to be valid")
	ErrInvalidKeyExchange                     = errors.New("Ratchet: peer's key exchange is invalid")
	ErrFailedToInitializeRatchet              = errors.New("Ratchet: failed to initialize")
	ErrInvalidPubkey                          = errors.New("Ratchet: invalid public key")
	ErrInvalidPublicIdentityKey               = errors.New("Ratchet: invalid public identity key")
	ErrInvalidSignature                       = errors.New("Ratchet: invalid signature")
	ErrKeyExchangeKeysNotIsomorphicallyEqual  = errors.New("Ratchet: key exchange and identity public keys must be isomorphically equal")
	ErrFailedToLoadPQRatchet                  = errors.New("Ratchet: failed to load PQ Ratchet from state")
	ErrImportPQDh0                            = errors.New("Ratchet: failed to import PQ DH0 from exchange blob")
	ErrCSIDHSharedSecret                      = errors.New("Ratchet: failed to compute shared secret from PQDH0")
	ErrCSIDHPrivateExport                     = errors.New("Ratchet: CSIDH: failed to export private key")
	ErrCSIDHPrivateImport                     = errors.New("Ratchet: CSIDH: failed to import private key")
	ErrCSIDHPublicExport                      = errors.New("Ratchet: CSIDH: failed to export public key")
	ErrCSIDHPublicImport                      = errors.New("Ratchet: CSIDH: failed to import public key")
	ErrCSIDHInvalidPublicKey                  = errors.New("Ratchet: CSIDH public key validation failure")
	ErrInconsistentState                       = errors.New("Ratchet: the state is inconsistent")

	// These constants are used as the label argument to deriveKey to derive
	// independent keys from a master key.

	chainKeyLabel      = []byte("chain key")
	headerKeyLabel     = []byte("header key")
	nextHeaderKeyLabel = []byte("next header key")
	rootKeyLabel       = []byte("root key")
	rootKeyUpdateLabel = []byte("root key update")
	messageKeyLabel    = []byte("message key")
	chainKeyStepLabel  = []byte("chain key step")
)

// keyExchange is structure containing the public keys
type keyExchange struct {
	Dh0   []byte
	Dh1   []byte
	PQDh0 []byte
	PQDh1 []byte
}

func (k *keyExchange) Wipe() {
	utils.ExplicitBzero(k.Dh0)
	utils.ExplicitBzero(k.Dh1)
}

// messageKey is structure containing the data associated with the message key
type messageKey struct {
	Num          uint32
	Key          *memguard.LockedBuffer
	CreationTime int64
}

// savedKeys is structure containing the saved keys from delayed messages
type savedKeys struct {
	HeaderKey   *memguard.LockedBuffer
	MessageKeys []*messageKey
}

type cborMessageKey struct {
	Num          uint32
	Key          []byte
	CreationTime int64
}
type cborSavedKeys struct {
	HeaderKey   []byte
	MessageKeys []*cborMessageKey
}

// MarshalBinary implements encoding.BinaryUnmarshaler interface
func (s *savedKeys) MarshalBinary() ([]byte, error) {
	tmp := &cborSavedKeys{}
	if s.HeaderKey.IsAlive() {
		tmp.HeaderKey = s.HeaderKey.Bytes()
		for _, m := range s.MessageKeys {
			tmp.MessageKeys = append(tmp.MessageKeys, &cborMessageKey{Num: m.Num, Key: m.Key.Bytes(), CreationTime: m.CreationTime})
		}
	}
	return cbor.Marshal(tmp)
}

// UnmarshalBinary instantiates memguard.LockedBuffer instances for each deserialized key
func (s *savedKeys) UnmarshalBinary(data []byte) error {
	tmp := &cborSavedKeys{}

	err := cbor.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(tmp, "", " ")
	fmt.Printf("Unmarshaled ratchet:\n%s", b)
	if len(tmp.HeaderKey) == keySize {
		s.HeaderKey = memguard.NewBufferFromBytes(tmp.HeaderKey)
		for _, m := range tmp.MessageKeys {
			if len(m.Key) == keySize {
				s.MessageKeys = append(s.MessageKeys, &messageKey{Num: m.Num,
					Key: memguard.NewBufferFromBytes(m.Key), CreationTime: m.CreationTime})
			}
		}
	}
	return err
}

// state constains all the data associated with a ratchet
type state struct {
	SavedKeys            []*savedKeys
	RootKey              []byte
	SendHeaderKey        []byte
	RecvHeaderKey        []byte
	NextSendHeaderKey    []byte
	NextRecvHeaderKey    []byte
	SendChainKey         []byte
	RecvChainKey         []byte
	SendRatchetPrivate   []byte
	RecvRatchetPublic    []byte
	SendPQRatchetPrivate []byte
	RecvPQRatchetPublic  []byte
	SendCount            uint32
	RecvCount            uint32
	PrevSendCount        uint32
	Private0             []byte
	Private1             []byte
	PQPrivate0           []byte
	PQPrivate1           []byte
	Ratchet              bool
}

// savedKey contains a message key and timestamp for a message which has not
// been received. The timestamp comes from the message by which we learn of the
// missing message.
type savedKey struct {
	key       *memguard.LockedBuffer
	timestamp time.Time
}

// Ratchet stucture contains the per-contact, crypto state.
type Ratchet struct {
	// Now is an optional function that will be used to get the current
	// time. If nil, time.Now is used.
	Now func() time.Time

	// rootKey gets updated by the DH ratchet.
	rootKey *memguard.LockedBuffer // 32 bytes long
	// Header keys are used to encrypt message headers.
	sendHeaderKey, recvHeaderKey         *memguard.LockedBuffer // 32 bytes long
	nextSendHeaderKey, nextRecvHeaderKey *memguard.LockedBuffer // 32 bytes long
	// Chain keys are used for forward secrecy updating.
	sendChainKey, recvChainKey *memguard.LockedBuffer // 32 bytes long

	// Ratchet counts apply to both ECDH and CSIDH Ratchets
	sendCount, recvCount uint32
	prevSendCount        uint32

	// DH Ratchet keys
	sendRatchetPrivate, recvRatchetPublic *memguard.LockedBuffer // 32 bytes long

	// CSIDH Ratchet keys
	sendPQRatchetPrivate *csidh.PrivateKey
	recvPQRatchetPublic  *csidh.PublicKey

	// ratchet is true if we will send a new ratchet value in the next message.
	ratchet bool

	// saved is a map from a header key to a map from sequence number to
	// message key.
	saved map[*memguard.LockedBuffer]map[uint32]savedKey

	// kxPrivate0 and kxPrivate1 contain curve25519 private values during
	// the key exchange phase. They are not valid once key exchange has
	// completed.
	kxPrivate0 *memguard.LockedBuffer
	kxPrivate1 *memguard.LockedBuffer

	// kxPQPrivate0 and kxPQPrivate1 contain CSIDH private keys during
	// the key exchange phase. They are not valid once key exchange has
	// completed.
	kxPQPrivate0 *csidh.PrivateKey
	kxPQPrivate1 *csidh.PrivateKey

	rand io.Reader
}

func (r *Ratchet) randBytes(buf []byte) {
	if _, err := io.ReadFull(r.rand, buf); err != nil {
		panic(err)
	}
}

// NewRatchetFromBytes takes ownership of data and
// unmarshals it into a new *Ratchet. The bytes are
// wiped afterwards. The new *Ratchet is returned unless
// there's an error.
func NewRatchetFromBytes(rand io.Reader, data []byte) (*Ratchet, error) {
	defer utils.ExplicitBzero(data)
	state := state{}
	if err := cbor.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return newRatchetFromState(rand, &state)
}

// newRatchetFromState unmarshals state into a new ratchet.
// state's fields are wiped in the process of copying them.
func newRatchetFromState(rand io.Reader, s *state) (*Ratchet, error) {
	r := &Ratchet{
		rand:          rand,
		saved:         make(map[*memguard.LockedBuffer]map[uint32]savedKey),
		sendCount:     s.SendCount,
		recvCount:     s.RecvCount,
		prevSendCount: s.PrevSendCount,
		ratchet:       s.Ratchet,
	}
	if s.RootKey != nil {
		r.rootKey = memguard.NewBufferFromBytes(s.RootKey)
	}
	if s.SendHeaderKey != nil {
		r.sendHeaderKey = memguard.NewBufferFromBytes(s.SendHeaderKey)
	}
	if s.RecvHeaderKey != nil {
		r.recvHeaderKey = memguard.NewBufferFromBytes(s.RecvHeaderKey)
	}
	if s.NextSendHeaderKey != nil {
		r.nextSendHeaderKey = memguard.NewBufferFromBytes(s.NextSendHeaderKey)
	}
	if s.NextRecvHeaderKey != nil {
		r.nextRecvHeaderKey = memguard.NewBufferFromBytes(s.NextRecvHeaderKey)
	}
	if s.SendChainKey != nil {
		r.sendChainKey = memguard.NewBufferFromBytes(s.SendChainKey)
	}
	if s.RecvChainKey != nil {
		r.recvChainKey = memguard.NewBufferFromBytes(s.RecvChainKey)
	}

	// DH Ratchet
	if s.SendRatchetPrivate != nil {
		r.sendRatchetPrivate = memguard.NewBufferFromBytes(s.SendRatchetPrivate)
	}
	if s.RecvRatchetPublic != nil {
		r.recvRatchetPublic = memguard.NewBufferFromBytes(s.RecvRatchetPublic)
	}
	// CSIDH Ratchet
	if s.SendPQRatchetPrivate != nil {
		r.sendPQRatchetPrivate = new(csidh.PrivateKey)
		ok := r.sendPQRatchetPrivate.Import(s.SendPQRatchetPrivate)
		if !ok {
			return nil, ErrCSIDHPrivateImport
		}
	}
	if s.RecvPQRatchetPublic != nil {
		r.recvPQRatchetPublic = new(csidh.PublicKey)
		ok := r.recvPQRatchetPublic.Import(s.RecvPQRatchetPublic)
		if !ok {
			return nil, ErrCSIDHPublicImport
		}
	}

	// DH keys
	if s.Private0 != nil && len(s.Private0) > 0 {
		r.kxPrivate0 = memguard.NewBufferFromBytes(s.Private0)
	}
	if s.Private1 != nil && len(s.Private1) > 0 {
		r.kxPrivate1 = memguard.NewBufferFromBytes(s.Private1)
	}
	// CSIDH keys
	if s.PQPrivate0 != nil && len(s.PQPrivate0) > 0 {
		r.kxPQPrivate0 = new(csidh.PrivateKey)
		ok := r.kxPQPrivate0.Import(s.PQPrivate0)
		if !ok {
			return nil, ErrFailedToLoadPQRatchet
		}
	}
	if s.PQPrivate1 != nil && len(s.PQPrivate1) > 0 {
		r.kxPQPrivate1 = new(csidh.PrivateKey)
		ok := r.kxPQPrivate1.Import(s.PQPrivate1)
		if !ok {
			return nil, ErrFailedToLoadPQRatchet
		}
	}

	for _, saved := range s.SavedKeys {
		if saved.HeaderKey.Size() != keySize {
			return nil, ErrSerialisedKeyLength
		}

		messageKeys := make(map[uint32]savedKey)
		for _, messageKey := range saved.MessageKeys {
			if messageKey.Key.Size() != keySize {
				return nil, ErrSerialisedKeyLength
			}
			savedKey := savedKey{key: messageKey.Key}
			savedKey.timestamp = time.Unix(0, messageKey.CreationTime)
			messageKeys[messageKey.Num] = savedKey
		}

		r.saved[saved.HeaderKey] = messageKeys
	}
	return r, nil
}

// InitRatchet initializes a ratchet struct
func InitRatchet(rand io.Reader) (*Ratchet, error) {
	r := &Ratchet{
		rand:  rand,
		saved: make(map[*memguard.LockedBuffer]map[uint32]savedKey),
	}

	var err error
	r.kxPrivate0, err = memguard.NewBufferFromReader(rand, privateKeySize)
	if err != nil {
		return nil, err
	}
	r.kxPrivate1, err = memguard.NewBufferFromReader(rand, privateKeySize)
	if err != nil {
		return nil, err
	}
	r.kxPQPrivate0 = new(csidh.PrivateKey)
	err = csidh.GeneratePrivateKey(r.kxPQPrivate0, rand)
	if err != nil {
		return nil, err
	}
	r.kxPQPrivate1 = new(csidh.PrivateKey)
	err = csidh.GeneratePrivateKey(r.kxPQPrivate1, rand)
	if err != nil {
		return nil, err
	}

	r.sendHeaderKey = memguard.NewBuffer(keySize)
	r.recvHeaderKey = memguard.NewBuffer(keySize)
	r.nextSendHeaderKey = memguard.NewBuffer(keySize)
	r.nextRecvHeaderKey = memguard.NewBuffer(keySize)
	r.sendChainKey = memguard.NewBuffer(keySize)
	r.recvChainKey = memguard.NewBuffer(keySize)
	r.rootKey = memguard.NewBuffer(keySize)

	// DH Ratchet keys
	r.sendRatchetPrivate = memguard.NewBuffer(keySize)
	r.recvRatchetPublic = memguard.NewBuffer(keySize)

	// CSIDH Ratchet keys
	r.sendPQRatchetPrivate = new(csidh.PrivateKey)
	r.recvPQRatchetPublic = new(csidh.PublicKey)

	return r, nil
}

// CreateKeyExchange returns a byte slice which is meant to
// be transmitted to the other party via an encrypted and authenticated
// communications channel. The other party can then call their
// Ratchet's ProcessKeyExchange method to process this byte blob
// and establish a communications channel with the sender.
func (r *Ratchet) CreateKeyExchange() ([]byte, error) {
	if r.kxPrivate0 == r.kxPrivate1 && r.kxPrivate0 == nil {
		return nil, ErrHandshakeAlreadyComplete
	}
	if r.kxPrivate0.IsAlive() != r.kxPrivate1.IsAlive() {
		return nil, ErrInconsistentState
	}
	if r.kxPrivate0.IsAlive() == false {
		return nil, ErrHandshakeAlreadyComplete
	}
	public0 := [publicKeySize]byte{}
	public1 := [publicKeySize]byte{}
	curve25519.ScalarBaseMult(&public0, r.kxPrivate0.ByteArray32())
	curve25519.ScalarBaseMult(&public1, r.kxPrivate1.ByteArray32())
	kx := &keyExchange{
		Dh0: public0[:],
		Dh1: public1[:],
	}
	pqpub0 := new(csidh.PublicKey)
	pqpub1 := new(csidh.PublicKey)
	csidh.GeneratePublicKey(pqpub0, r.kxPQPrivate0, r.rand)
	csidh.GeneratePublicKey(pqpub1, r.kxPQPrivate1, r.rand)
	kx.PQDh0 = make([]byte, csidh.PublicKeySize)
	ok := pqpub0.Export(kx.PQDh0)
	if !ok {
		return nil, ErrCSIDHPublicExport
	}
	kx.PQDh1 = make([]byte, csidh.PublicKeySize)
	ok = pqpub1.Export(kx.PQDh1)
	if !ok {
		return nil, ErrCSIDHPublicExport
	}

	serialized, err := cbor.Marshal(kx)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

// deriveKey takes an HMAC object and a label and calculates out = HMAC(k, label).
func deriveKey(key *memguard.LockedBuffer, label []byte, h hash.Hash) {
	h.Reset()
	h.Write(label)
	if !key.IsMutable() {
		key.Melt()
		defer key.Freeze()
	}
	h.Sum(key.Bytes()[:0])
	if key.Size() != keySize {
		panic("Hash function wrong size")
	}
}

// ProcessKeyExchange processes the data of a keyExchange
// which is used to establish an encrypted authenticated
// communications channel.
func (r *Ratchet) ProcessKeyExchange(exchangePayload []byte) error {
	kx := new(keyExchange)
	err := cbor.Unmarshal(exchangePayload, &kx)
	if err != nil {
		return err
	}
	defer kx.Wipe()
	return r.completeKeyExchange(kx)
}

// completeKeyExchange takes a keyExchange message from the other party and
// establishes the ratchet.
func (r *Ratchet) completeKeyExchange(kx *keyExchange) error {
	if r.kxPrivate0 == r.kxPrivate1 && r.kxPrivate0 == nil {
		return ErrHandshakeAlreadyComplete
	}
	if r.kxPrivate0.IsAlive() != r.kxPrivate1.IsAlive() {
		return ErrInconsistentState
	}
	if r.kxPrivate0.IsAlive() == false {
		return ErrHandshakeAlreadyComplete
	}
	if len(kx.Dh0) != publicKeySize || len(kx.Dh1) != publicKeySize {
		return ErrInvalidKeyExchange
	}
	if len(kx.PQDh0) != csidh.PublicKeySize || len(kx.PQDh1) != csidh.PublicKeySize {
		return ErrInvalidKeyExchange
	}

	public0 := memguard.NewBuffer(publicKeySize)
	curve25519.ScalarBaseMult(public0.ByteArray32(), r.kxPrivate0.ByteArray32())
	var amAlice bool
	switch bytes.Compare(public0.Bytes(), kx.Dh0) {
	case -1:
		amAlice = true
	case 1:
		amAlice = false
	case 0:
		return ErrEchoedDHValues
	}
	public0.Destroy()

	theirDH := memguard.NewBufferFromBytes(kx.Dh0)
	sharedKey := memguard.NewBuffer(sharedKeySize)
	curve25519.ScalarMult(sharedKey.ByteArray32(), r.kxPrivate0.ByteArray32(), theirDH.ByteArray32())
	theirDH.Destroy()

	pqSharedSecret := &[64]byte{}
	theirPQPublicKey0 := new(csidh.PublicKey)
	ok := theirPQPublicKey0.Import(kx.PQDh0)
	if !ok {
		return ErrCSIDHPublicImport
	}
	ok = csidh.Validate(theirPQPublicKey0, r.rand)
	if !ok {
		return ErrCSIDHInvalidPublicKey
	}
	ok = csidh.DeriveSecret(pqSharedSecret, theirPQPublicKey0, r.kxPQPrivate0, r.rand)
	if !ok {
		return ErrCSIDHSharedSecret
	}

	h := hmac.New(sha3.New256, append(sharedKey.Bytes(), pqSharedSecret[:]...))
	deriveKey(r.rootKey, rootKeyLabel, h)
	sharedKey.Destroy()

	if amAlice {
		deriveKey(r.recvHeaderKey, headerKeyLabel, h)
		deriveKey(r.nextSendHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.nextRecvHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.recvChainKey, chainKeyLabel, h)
		r.recvRatchetPublic.Melt()
		r.recvRatchetPublic.Copy(kx.Dh1)
		r.recvRatchetPublic.Freeze()
		ok = r.recvPQRatchetPublic.Import(kx.PQDh1)
		if !ok {
			return ErrCSIDHPublicImport
		}
		ok = csidh.Validate(r.recvPQRatchetPublic, r.rand)
		if !ok {
			return ErrCSIDHInvalidPublicKey
		}
	} else {
		deriveKey(r.sendHeaderKey, headerKeyLabel, h)
		deriveKey(r.nextRecvHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.nextSendHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.sendChainKey, chainKeyLabel, h)
		r.sendRatchetPrivate.Melt()
		r.sendRatchetPrivate.Copy(r.kxPrivate1.Bytes())
		r.sendRatchetPrivate.Freeze()
		r.sendPQRatchetPrivate = r.kxPQPrivate1
	}

	r.ratchet = amAlice

	r.kxPrivate0.Melt()
	r.kxPrivate1.Melt()
	r.kxPrivate0.Destroy()
	r.kxPrivate1.Destroy()
	r.kxPrivate0 = nil
	r.kxPrivate1 = nil
	return nil
}

// Encrypt acts like append() but appends an encrypted version of msg to out.
func (r *Ratchet) Encrypt(out, msg []byte) ([]byte, error) {
	if r.ratchet {
		var err error
		r.sendRatchetPrivate, err = memguard.NewBufferFromReader(r.rand, keySize)
		if err != nil {
			return nil, err
		}
		r.sendPQRatchetPrivate = new(csidh.PrivateKey)
		err = csidh.GeneratePrivateKey(r.sendPQRatchetPrivate, r.rand)
		if err != nil {
			return nil, err
		}

		r.sendHeaderKey.Melt()
		r.sendHeaderKey.Copy(r.nextSendHeaderKey.ByteArray32()[:])
		r.sendHeaderKey.Freeze()

		sharedKey := memguard.NewBuffer(sharedKeySize)
		keyMaterial := memguard.NewBuffer(sharedKeySize)
		curve25519.ScalarMult(sharedKey.ByteArray32(), r.sendRatchetPrivate.ByteArray32(), r.recvRatchetPublic.ByteArray32())

		pqSharedKey := memguard.NewBuffer(csidh.SharedSecretSize)
		ok := csidh.DeriveSecret(pqSharedKey.ByteArray64(), r.recvPQRatchetPublic, r.sendPQRatchetPrivate, r.rand)
		if !ok {
			return nil, ErrCSIDHSharedSecret
		}

		sha := sha3.New256()
		sha.Write(rootKeyUpdateLabel)
		sha.Write(r.rootKey.Bytes())
		sha.Write(sharedKey.Bytes())
		sha.Write(pqSharedKey.Bytes())
		sha.Sum(keyMaterial.Bytes()[:0])
		h := hmac.New(sha3.New256, keyMaterial.Bytes())

		deriveKey(r.rootKey, rootKeyLabel, h)
		deriveKey(r.nextSendHeaderKey, headerKeyLabel, h)
		deriveKey(r.sendChainKey, chainKeyLabel, h)
		r.prevSendCount, r.sendCount = r.sendCount, 0
		r.ratchet = false
	}

	h := hmac.New(sha3.New256, r.sendChainKey.Bytes())
	messageKey := memguard.NewBuffer(keySize)
	deriveKey(messageKey, messageKeyLabel, h)
	deriveKey(r.sendChainKey, chainKeyStepLabel, h)

	var sendRatchetPublic [publicKeySize]byte
	curve25519.ScalarBaseMult(&sendRatchetPublic, r.sendRatchetPrivate.ByteArray32())

	sendPQRatchetPublic := new(csidh.PublicKey)
	csidh.GeneratePublicKey(sendPQRatchetPublic, r.sendPQRatchetPrivate, r.rand)
	sendPQRatchetPublicBytes := make([]byte, csidh.PublicKeySize)
	ok := sendPQRatchetPublic.Export(sendPQRatchetPublicBytes)
	if !ok {
		return nil, ErrCSIDHPublicExport
	}

	var header [headerSize]byte
	var headerNonce, messageNonce [nonceSize]byte
	r.randBytes(headerNonce[:])
	r.randBytes(messageNonce[:])

	binary.LittleEndian.PutUint32(header[0:4], r.sendCount)
	binary.LittleEndian.PutUint32(header[4:8], r.prevSendCount)
	copy(header[8:], sendRatchetPublic[:])
	copy(header[PQRatchetPublicKeyInHeaderOffset:], sendPQRatchetPublicBytes)
	copy(header[nonceInHeaderOffset:], messageNonce[:])
	out = append(out, headerNonce[:]...)
	out = secretbox.Seal(out, header[:], &headerNonce, r.sendHeaderKey.ByteArray32())
	r.sendCount++

	return secretbox.Seal(out, msg, &messageNonce, messageKey.ByteArray32()), nil
}

// trySavedKeys tries to decrypt the ciphertext using keys saved for delayed messages.
func (r *Ratchet) trySavedKeys(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < sealedHeaderSize {
		return nil, ErrRatchetHeaderTooSmall
	}

	sealedHeader := ciphertext[:sealedHeaderSize]
	var nonce [nonceSize]byte
	copy(nonce[:], sealedHeader)
	sealedHeader = sealedHeader[len(nonce):]

	for headerKey, messageKeys := range r.saved {
		header, ok := secretbox.Open(nil, sealedHeader, &nonce, headerKey.ByteArray32())
		if !ok {
			continue
		}
		if len(header) != headerSize {
			continue
		}
		msgNum := binary.LittleEndian.Uint32(header[:4])
		msgKey, ok := messageKeys[msgNum]
		if !ok {
			// This is a fairly common case: the message key might
			// not have been saved because it's the next message
			// key.
			return nil, nil
		}

		sealedMessage := ciphertext[sealedHeaderSize:]
		copy(nonce[:], header[nonceInHeaderOffset:])
		msg, ok := secretbox.Open(nil, sealedMessage, &nonce, msgKey.key.ByteArray32())
		if !ok {
			return nil, ErrCorruptMessage
		}
		delete(messageKeys, msgNum)
		msgKey.key.Destroy()
		if len(messageKeys) == 0 {
			delete(r.saved, headerKey)
			headerKey.Destroy()
		}
		return msg, nil
	}

	return nil, nil
}

// saveKeys takes a header key, the current chain key, a received message
// number and the expected message number and advances the chain key as needed.
// It returns the message key for given given message number and the new chain
// key. If any messages have been skipped over, it also returns savedKeys, a
// map suitable for merging with r.saved, that contains the message keys for
// the missing messages.
func (r *Ratchet) saveKeys(headerKey, recvChainKey *memguard.LockedBuffer, messageNum, receivedCount uint32) (provisionalChainKey, messageKey *memguard.LockedBuffer, savedKeys map[*memguard.LockedBuffer]map[uint32]savedKey, err error) {
	if messageNum < receivedCount {
		// This is a message from the past, but we didn't have a saved
		// key for it, which means that it's a duplicate message or we
		// expired the save key.
		err = ErrDuplicateOrDelayed
		return
	}

	missingMessages := messageNum - receivedCount
	if missingMessages > MaxMissingMessages {
		err = ErrMessageExceedsReorderingLimit
		return
	}

	// messageKeys maps from message number to message key.
	var messageKeys map[uint32]savedKey
	var now time.Time
	if missingMessages > 0 {
		messageKeys = make(map[uint32]savedKey)
	}
	if r.Now == nil {
		now = time.Now()
	} else {
		now = r.Now()
	}

	provisionalChainKey = memguard.NewBuffer(keySize)
	provisionalChainKey.Copy(recvChainKey.Bytes())

	for n := receivedCount; n <= messageNum; n++ {
		h := hmac.New(sha3.New256, provisionalChainKey.Bytes())
		messageKey = memguard.NewBuffer(keySize)
		deriveKey(messageKey, messageKeyLabel, h)
		deriveKey(provisionalChainKey, chainKeyStepLabel, h)

		if n < messageNum {
			messageKeys[n] = savedKey{messageKey, now}
		}
	}

	if messageKeys != nil {
		savedKeys = make(map[*memguard.LockedBuffer]map[uint32]savedKey)
		hkey := memguard.NewBuffer(keySize)
		hkey.Copy(headerKey.Bytes())
		savedKeys[hkey] = messageKeys
	}

	return
}

// mergeSavedKeys takes a map of saved message keys from saveKeys and merges it
// into r.saved.
func (r *Ratchet) mergeSavedKeys(newKeys map[*memguard.LockedBuffer]map[uint32]savedKey) {
	for headerKey, newMessageKeys := range newKeys {
		messageKeys, ok := r.saved[headerKey]
		if ok {
			// We already have it so Destroy the new copy.
			headerKey.Destroy()
			for _, messageKey := range newMessageKeys {
				messageKey.key.Destroy()
			}
		} else {
			r.saved[headerKey] = newMessageKeys
			continue
		}

		for n, messageKey := range newMessageKeys {
			messageKeys[n] = messageKey
		}
	}
}

func (r *Ratchet) wipeSavedKeys() {
	for headerKey, keys := range r.saved {
		for _, savedKey := range keys {
			savedKey.key.Destroy()
		}
		delete(r.saved, headerKey)
		headerKey.Destroy()
	}
}

// Decrypt decrypts a message
func (r *Ratchet) Decrypt(ciphertext []byte) ([]byte, error) {
	msg, err := r.trySavedKeys(ciphertext)
	if err != nil || msg != nil {
		return msg, err
	}

	sealedHeader := ciphertext[:sealedHeaderSize]
	sealedMessage := ciphertext[sealedHeaderSize:]
	var nonce [nonceSize]byte
	copy(nonce[:], sealedHeader)
	sealedHeader = sealedHeader[len(nonce):]

	header, ok := secretbox.Open(nil, sealedHeader, &nonce, r.recvHeaderKey.ByteArray32())
	ok = ok && !utils.CtIsZero(r.recvHeaderKey.Bytes())

	if ok {
		if len(header) != headerSize {
			return nil, ErrIncorrectHeaderSize
		}

		messageNum := binary.LittleEndian.Uint32(header[:4])
		provisionalChainKey, messageKey, savedKeys, err := r.saveKeys(r.recvHeaderKey, r.recvChainKey, messageNum, r.recvCount)
		if err != nil {
			return nil, err
		}

		copy(nonce[:], header[nonceInHeaderOffset:])
		msg, ok := secretbox.Open(nil, sealedMessage, &nonce, messageKey.ByteArray32())
		if !ok {
			return nil, ErrCorruptMessage
		}

		r.recvChainKey.Melt()
		r.recvChainKey.Copy(provisionalChainKey.Bytes())
		r.recvChainKey.Freeze()

		r.mergeSavedKeys(savedKeys)
		r.recvCount = messageNum + 1
		return msg, nil
	}

	header, ok = secretbox.Open(nil, sealedHeader, &nonce, r.nextRecvHeaderKey.ByteArray32())
	if !ok {
		return nil, ErrCannotDecrypt
	}
	if len(header) != headerSize {
		return nil, ErrIncorrectHeaderSize
	}

	if r.ratchet {
		return nil, ErrNextEncryptedMessageWithoutRatchetFlag
	}

	messageNum := binary.LittleEndian.Uint32(header[:4])
	prevMessageCount := binary.LittleEndian.Uint32(header[4:8])

	_, _, oldSavedKeys, err := r.saveKeys(r.recvHeaderKey, r.recvChainKey, prevMessageCount, r.recvCount)
	if err != nil {
		return nil, err
	}

	dhPublic := memguard.NewBuffer(keySize)
	sharedKey := memguard.NewBuffer(keySize)
	keyMaterial := memguard.NewBuffer(keySize)
	dhPublic.Copy(header[8:])

	curve25519.ScalarMult(sharedKey.ByteArray32(), r.sendRatchetPrivate.ByteArray32(), dhPublic.ByteArray32())

	pqSharedKey := memguard.NewBuffer(csidh.SharedSecretSize)
	theirPQRatchetPublic := new(csidh.PublicKey)
	theirPQRatchetPublic.Import(header[PQRatchetPublicKeyInHeaderOffset : PQRatchetPublicKeyInHeaderOffset+csidh.PublicKeySize])
	ok = csidh.Validate(theirPQRatchetPublic, r.rand)
	if !ok {
		return nil, ErrCSIDHInvalidPublicKey
	}
	ok = csidh.DeriveSecret(pqSharedKey.ByteArray64(), theirPQRatchetPublic, r.sendPQRatchetPrivate, r.rand)
	if !ok {
		return nil, ErrCSIDHSharedSecret
	}

	sha := sha3.New256()
	sha.Write(rootKeyUpdateLabel)
	sha.Write(r.rootKey.Bytes())
	sha.Write(sharedKey.Bytes())
	sha.Write(pqSharedKey.Bytes())

	var rootKeyHMAC hash.Hash
	chainKey := memguard.NewBuffer(keySize)

	sha.Sum(keyMaterial.Bytes()[:0])
	rootKeyHMAC = hmac.New(sha3.New256, keyMaterial.Bytes())
	deriveKey(r.rootKey, rootKeyLabel, rootKeyHMAC)
	deriveKey(chainKey, chainKeyLabel, rootKeyHMAC)

	provisionalChainKey, messageKey, savedKeys, err := r.saveKeys(r.nextRecvHeaderKey, chainKey, messageNum, 0)
	if err != nil {
		return nil, err
	}

	copy(nonce[:], header[nonceInHeaderOffset:])
	msg, ok = secretbox.Open(nil, sealedMessage, &nonce, messageKey.ByteArray32())
	if !ok {
		return nil, ErrCorruptMessage
	}

	r.recvChainKey.Melt()
	r.recvChainKey.Copy(provisionalChainKey.Bytes())
	r.recvChainKey.Freeze()

	r.recvHeaderKey.Melt()
	r.recvHeaderKey.Copy(r.nextRecvHeaderKey.Bytes())
	r.recvHeaderKey.Freeze()

	deriveKey(r.nextRecvHeaderKey, headerKeyLabel, rootKeyHMAC)

	r.sendRatchetPrivate.Melt()
	r.sendRatchetPrivate.Wipe()
	r.sendRatchetPrivate.Freeze()

	r.sendPQRatchetPrivate = new(csidh.PrivateKey)

	r.recvRatchetPublic.Melt()
	r.recvRatchetPublic.Copy(dhPublic.Bytes())
	r.recvRatchetPublic.Freeze()

	r.recvPQRatchetPublic = theirPQRatchetPublic

	r.recvCount = messageNum + 1
	r.mergeSavedKeys(oldSavedKeys)
	r.mergeSavedKeys(savedKeys)
	r.ratchet = true

	return msg, nil
}

// Save transforms the object into a stream
func (r *Ratchet) Save() (data []byte, err error) {
	s, err := r.marshal(time.Now(), RatchetKeyMaxLifetime)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(s)
}

// Marshal transforms the object into a stream
func (r *Ratchet) marshal(now time.Time, lifetime time.Duration) (*state, error) {
	s := &state{
		RootKey:            r.rootKey.Bytes(),
		SendHeaderKey:      r.sendHeaderKey.Bytes(),
		RecvHeaderKey:      r.recvHeaderKey.Bytes(),
		NextSendHeaderKey:  r.nextSendHeaderKey.Bytes(),
		NextRecvHeaderKey:  r.nextRecvHeaderKey.Bytes(),
		SendChainKey:       r.sendChainKey.Bytes(),
		RecvChainKey:       r.recvChainKey.Bytes(),
		SendRatchetPrivate: r.sendRatchetPrivate.Bytes(),
		RecvRatchetPublic:  r.recvRatchetPublic.Bytes(),
		SendCount:          r.sendCount,
		RecvCount:          r.recvCount,
		PrevSendCount:      r.prevSendCount,
		Ratchet:            r.ratchet,
	}

	s.SendPQRatchetPrivate = make([]byte, csidh.PrivateKeySize)
	r.sendPQRatchetPrivate.Export(s.SendPQRatchetPrivate)
	s.RecvPQRatchetPublic = make([]byte, csidh.PublicKeySize)
	r.recvPQRatchetPublic.Export(s.RecvPQRatchetPublic)

	if r.kxPrivate0 != nil {
		s.Private0 = r.kxPrivate0.Bytes()
	}
	if r.kxPrivate1 != nil {
		s.Private1 = r.kxPrivate1.Bytes()
	}
	if r.kxPQPrivate0 != nil {
		s.PQPrivate0 = make([]byte, csidh.PrivateKeySize)
		r.kxPQPrivate0.Export(s.PQPrivate0)
	}
	if r.kxPQPrivate1 != nil {
		s.PQPrivate1 = make([]byte, csidh.PrivateKeySize)
		r.kxPQPrivate1.Export(s.PQPrivate1)
	}

	for headerKey, messageKeys := range r.saved {
		keys := make([]*messageKey, 0, len(messageKeys))
		for messageNum, savedKey := range messageKeys {
			if now.Sub(savedKey.timestamp) > lifetime {
				continue
			}
			keys = append(keys, &messageKey{
				Num:          messageNum,
				Key:          savedKey.key,
				CreationTime: savedKey.timestamp.UnixNano(),
			})
		}
		s.SavedKeys = append(s.SavedKeys, &savedKeys{
			HeaderKey:   headerKey,
			MessageKeys: keys,
		})
	}

	return s, nil
}

// DestroyRatchet destroys the ratchet
func DestroyRatchet(r *Ratchet) {
	r.rootKey.Destroy()
	r.sendHeaderKey.Destroy()
	r.recvHeaderKey.Destroy()
	r.nextSendHeaderKey.Destroy()
	r.nextRecvHeaderKey.Destroy()
	r.sendChainKey.Destroy()
	r.recvChainKey.Destroy()
	r.sendRatchetPrivate.Destroy()
	r.recvRatchetPublic.Destroy()
	r.sendPQRatchetPrivate = nil
	r.recvPQRatchetPublic = nil
	r.sendCount, r.recvCount = uint32(0), uint32(0)
	r.prevSendCount = uint32(0)
	if r.kxPrivate0 != nil {
		r.kxPrivate0.Destroy()
	}
	if r.kxPrivate1 != nil {
		r.kxPrivate1.Destroy()
	}
	r.kxPQPrivate0 = nil
	r.kxPQPrivate1 = nil
	r.wipeSavedKeys()
}
