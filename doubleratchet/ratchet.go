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

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/hybrid"

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
	ErrInconsistentState                      = errors.New("Ratchet: the state is inconsistent")

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

func array32p(b []byte) *[32]byte {
	if len(b) != 32 {
		panic("array32p slice not 32 bytes")
	}
	ar := [32]byte{}
	copy(ar[:], b)
	return &ar
}

func array32(b []byte) [32]byte {
	if len(b) != 32 {
		panic("array32 slice not 32 bytes")
	}
	ar := [32]byte{}
	copy(ar[:], b)
	return ar
}

// keyExchange is structure containing the public keys
type keyExchange struct {
	Dh0 []byte
	Dh1 []byte
}

func (k *keyExchange) Wipe() {
	utils.ExplicitBzero(k.Dh0)
	utils.ExplicitBzero(k.Dh1)
}

// messageKey is structure containing the data associated with the message key
type messageKey struct {
	Num          uint32
	Key          []byte
	CreationTime int64
}

// savedKeys is structure containing the saved keys from delayed messages
type savedKeys struct {
	HeaderKey   []byte
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
	tmp.HeaderKey = s.HeaderKey
	for _, m := range s.MessageKeys {
		tmp.MessageKeys = append(tmp.MessageKeys,
			&cborMessageKey{
				Num:          m.Num,
				Key:          m.Key,
				CreationTime: m.CreationTime,
			})
	}
	return cbor.Marshal(tmp)
}

// UnmarshalBinary instantiates instances for each deserialized key
func (s *savedKeys) UnmarshalBinary(data []byte) error {
	tmp := &cborSavedKeys{}

	err := cbor.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(tmp, "", " ")
	fmt.Printf("Unmarshaled keys in UnmarshalBinary, pre-unpack:\n%s", b)

	if len(tmp.HeaderKey) == keySize {
		s.HeaderKey = tmp.HeaderKey
		for _, m := range tmp.MessageKeys {
			if len(m.Key) == keySize {
				s.MessageKeys = append(s.MessageKeys,
					&messageKey{
						Num:          m.Num,
						Key:          m.Key,
						CreationTime: m.CreationTime,
					})
			}
		}
	}
	b, _ = json.MarshalIndent(s, "", " ")
	fmt.Printf("Unmarshaled keys in UnmarshalBinary post-unpack:\n%s", b)

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

// this method upgrades from the previously-deployed pre-hpqc-nike hybrid doubleratchet
func (s *state) Upgrade(scheme *hybrid.Scheme) error {
	x25519SendPrivate, err := scheme.First().UnmarshalBinaryPrivateKey(s.SendRatchetPrivate)
	if err != nil {
		return err
	}
	csidhSendPrivate, err := scheme.Second().UnmarshalBinaryPrivateKey(s.SendPQRatchetPrivate)
	if err != nil {
		return err
	}

	hybridSendPrivate := scheme.PrivateKeyFromKeys(x25519SendPrivate, csidhSendPrivate)

	s.SendRatchetPrivate = hybridSendPrivate.Bytes()

	if util.CtIsZero(s.RecvRatchetPublic) {
		panic("RecvRatchetPublic is all zeros")
	}
	if util.CtIsZero(s.RecvPQRatchetPublic) {
		panic("RecvPQRatchetPublic is all zeros")
	}

	x25519RecvPublic, err := scheme.First().UnmarshalBinaryPublicKey(s.RecvRatchetPublic)
	if err != nil {
		return err
	}
	csidhRecvPublic, err := scheme.Second().UnmarshalBinaryPublicKey(s.RecvPQRatchetPublic)
	if err != nil {
		return err
	}

	hybridRecvPublic := scheme.PublicKeyFromKeys(x25519RecvPublic, csidhRecvPublic)

	s.RecvRatchetPublic = hybridRecvPublic.Bytes()

	utils.ExplicitBzero(s.SendPQRatchetPrivate)
	utils.ExplicitBzero(s.RecvPQRatchetPublic)

	s.SendPQRatchetPrivate = []byte{}
	s.RecvPQRatchetPublic = []byte{}

	if s.Private0 != nil && s.Private1 != nil && s.PQPrivate0 != nil && s.PQPrivate1 != nil {

		kx25519p0, err := scheme.First().UnmarshalBinaryPrivateKey(s.Private0)
		if err != nil {
			return err
		}
		kxcsidhp0, err := scheme.Second().UnmarshalBinaryPrivateKey(s.PQPrivate0)
		if err != nil {
			return err
		}

		kxhybridp0 := scheme.PrivateKeyFromKeys(kx25519p0, kxcsidhp0)

		s.Private0 = kxhybridp0.Bytes()

		kx25519p1, err := scheme.First().UnmarshalBinaryPrivateKey(s.Private1)
		if err != nil {
			return err
		}
		kxcsidhp1, err := scheme.Second().UnmarshalBinaryPrivateKey(s.PQPrivate1)
		if err != nil {
			return err
		}

		kxhybridp1 := scheme.PrivateKeyFromKeys(kx25519p1, kxcsidhp1)

		s.Private1 = kxhybridp1.Bytes()

		utils.ExplicitBzero(s.PQPrivate0)
		utils.ExplicitBzero(s.PQPrivate1)

		s.PQPrivate0 = []byte{}
		s.PQPrivate1 = []byte{}

	}
	return nil
}

// savedKey contains a message key and timestamp for a message which has not
// been received. The timestamp comes from the message by which we learn of the
// missing message.
type savedKey struct {
	key       []byte
	timestamp time.Time
}

// Ratchet stucture contains the per-contact, crypto state.
type Ratchet struct {
	// Now is an optional function that will be used to get the current
	// time. If nil, time.Now is used.
	Now func() time.Time

	// rootKey gets updated by the DH ratchet.
	rootKey []byte
	// Header keys are used to encrypt message headers.
	sendHeaderKey, recvHeaderKey         []byte
	nextSendHeaderKey, nextRecvHeaderKey []byte
	// Chain keys are used for forward secrecy updating.
	sendChainKey, recvChainKey []byte

	// Ratchet counts apply to both ECDH and CSIDH Ratchets
	sendCount, recvCount uint32
	prevSendCount        uint32

	// DH Ratchet keys
	sendRatchetPrivate nike.PrivateKey
	recvRatchetPublic  nike.PublicKey

	// ratchet is true if we will send a new ratchet value in the next message.
	ratchet bool

	// saved is a map from a header key to a map from sequence number to
	// message key.
	saved map[[32]byte]map[uint32]savedKey

	// kxPrivate0 and kxPrivate1 contain curve25519 private values during
	// the key exchange phase. They are not valid once key exchange has
	// completed.
	kxPrivate0 nike.PrivateKey
	kxPrivate1 nike.PrivateKey

	scheme                       nike.Scheme
	headerSize, sealedHeaderSize int

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
func NewRatchetFromBytes(rand io.Reader, data []byte, scheme nike.Scheme) (*Ratchet, error) {
	if scheme == nil {
		panic("NewRatchetFromBytes: nike scheme cannot be nil")
	}
	defer utils.ExplicitBzero(data)
	state := state{}
	if err := cbor.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.PQPrivate0 != nil && state.PQPrivate1 != nil {
		err := state.Upgrade(scheme.(*hybrid.Scheme))
		if err != nil {
			return nil, fmt.Errorf("key upgrade failure: %s", err)
		}
	}
	b, _ := json.MarshalIndent(state, "", " ")
	fmt.Printf("Unmarshaled ratchet in NewRatchetFromBytes:\n%s", b)
	return newRatchetFromState(rand, &state, scheme)
}

// newRatchetFromState unmarshals state into a new ratchet.
// state's fields are wiped in the process of copying them.
func newRatchetFromState(rand io.Reader, s *state, scheme nike.Scheme) (*Ratchet, error) {
	r := &Ratchet{
		rand:              rand,
		scheme:            scheme,
		headerSize:        headerSize(scheme),
		sealedHeaderSize:  sealedHeaderSize(scheme),
		saved:             make(map[[32]byte]map[uint32]savedKey),
		sendCount:         s.SendCount,
		recvCount:         s.RecvCount,
		prevSendCount:     s.PrevSendCount,
		ratchet:           s.Ratchet,
		rootKey:           s.RootKey,
		sendHeaderKey:     s.SendHeaderKey,
		recvHeaderKey:     s.RecvHeaderKey,
		nextSendHeaderKey: s.NextSendHeaderKey,
		nextRecvHeaderKey: s.NextRecvHeaderKey,
		sendChainKey:      s.SendChainKey,
		recvChainKey:      s.RecvChainKey,
	}

	// DH Ratchet
	if s.SendRatchetPrivate != nil {
		r.sendRatchetPrivate = r.scheme.NewEmptyPrivateKey()
		err := r.sendRatchetPrivate.FromBytes(s.SendRatchetPrivate)
		if err != nil {
			return nil, err
		}
	}
	if s.RecvRatchetPublic != nil {
		r.recvRatchetPublic = r.scheme.NewEmptyPublicKey()
		err := r.recvRatchetPublic.FromBytes(s.RecvRatchetPublic)
		if err != nil {
			return nil, err
		}
	}

	// DH keys
	if s.Private0 != nil && len(s.Private0) > 0 {
		r.kxPrivate0 = r.scheme.NewEmptyPrivateKey()
		err := r.kxPrivate0.FromBytes(s.Private0)
		if err != nil {
			return nil, err
		}
	}
	if s.Private1 != nil && len(s.Private1) > 0 {
		r.kxPrivate1 = r.scheme.NewEmptyPrivateKey()
		err := r.kxPrivate1.FromBytes(s.Private1)
		if err != nil {
			return nil, err
		}
	}

	for _, saved := range s.SavedKeys {
		messageKeys := make(map[uint32]savedKey)
		for _, messageKey := range saved.MessageKeys {
			if len(messageKey.Key) != keySize {
				return nil, ErrSerialisedKeyLength
			}
			savedKey := savedKey{key: messageKey.Key}
			savedKey.timestamp = time.Unix(0, messageKey.CreationTime)
			messageKeys[messageKey.Num] = savedKey
		}
		r.saved[array32(saved.HeaderKey)] = messageKeys
	}
	return r, nil
}

// InitRatchet initializes a ratchet struct
func InitRatchet(rand io.Reader, scheme nike.Scheme) (*Ratchet, error) {
	r := &Ratchet{
		rand:             rand,
		saved:            make(map[[32]byte]map[uint32]savedKey),
		scheme:           scheme,
		headerSize:       headerSize(scheme),
		sealedHeaderSize: sealedHeaderSize(scheme),
	}
	var err error
	_, r.kxPrivate0, err = scheme.GenerateKeyPairFromEntropy(rand)
	if err != nil {
		return nil, err
	}

	_, r.kxPrivate1, err = scheme.GenerateKeyPairFromEntropy(rand)
	if err != nil {
		return nil, err
	}

	r.sendHeaderKey = make([]byte, keySize)
	r.recvHeaderKey = make([]byte, keySize)
	r.nextSendHeaderKey = make([]byte, keySize)
	r.nextRecvHeaderKey = make([]byte, keySize)
	r.sendChainKey = make([]byte, keySize)
	r.recvChainKey = make([]byte, keySize)
	r.rootKey = make([]byte, keySize)

	// DH Ratchet keys
	r.sendRatchetPrivate = scheme.NewEmptyPrivateKey()
	r.recvRatchetPublic = scheme.NewEmptyPublicKey()

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
	if (r.kxPrivate0 == nil) != (r.kxPrivate1 == nil) {
		return nil, ErrInconsistentState
	}
	if r.kxPrivate0 == nil {
		return nil, ErrHandshakeAlreadyComplete
	}
	public0 := r.scheme.DerivePublicKey(r.kxPrivate0)
	public1 := r.scheme.DerivePublicKey(r.kxPrivate1)
	kx := &keyExchange{
		Dh0: public0.Bytes(),
		Dh1: public1.Bytes(),
	}

	serialized, err := cbor.Marshal(kx)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

// deriveKey takes an HMAC object and a label and calculates out = HMAC(k, label).
func deriveKey(key []byte, label []byte, h hash.Hash) {
	if len(key) != 32 {
		panic("wtf")
	}
	h.Reset()
	h.Write(label)
	h.Sum(key[:0])
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
	if (r.kxPrivate0 == nil) != (r.kxPrivate1 == nil) {
		return ErrInconsistentState
	}
	if r.kxPrivate0 == nil {
		return ErrHandshakeAlreadyComplete
	}
	if len(kx.Dh0) != r.scheme.PublicKeySize() || len(kx.Dh1) != r.scheme.PublicKeySize() {
		return ErrInvalidKeyExchange
	}

	public0 := r.scheme.DerivePublicKey(r.kxPrivate0)
	var amAlice bool
	switch bytes.Compare(public0.Bytes(), kx.Dh0) {
	case -1:
		amAlice = true
	case 1:
		amAlice = false
	case 0:
		return ErrEchoedDHValues
	}
	public0.Reset()

	theirDH := r.scheme.NewEmptyPublicKey()
	err := theirDH.FromBytes(kx.Dh0)
	if err != nil {
		return err
	}
	sharedKey := r.scheme.DeriveSecret(r.kxPrivate0, theirDH)
	theirDH.Reset()

	h := hmac.New(sha3.New256, sharedKey)
	deriveKey(r.rootKey, rootKeyLabel, h)
	utils.ExplicitBzero(sharedKey)

	if amAlice {
		deriveKey(r.recvHeaderKey, headerKeyLabel, h)
		deriveKey(r.nextSendHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.nextRecvHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.recvChainKey, chainKeyLabel, h)
		r.recvRatchetPublic = r.scheme.NewEmptyPublicKey()
		err := r.recvRatchetPublic.FromBytes(kx.Dh1)
		if err != nil {
			return err
		}
	} else {
		deriveKey(r.sendHeaderKey, headerKeyLabel, h)
		deriveKey(r.nextRecvHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.nextSendHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.sendChainKey, chainKeyLabel, h)
		r.sendRatchetPrivate = r.scheme.NewEmptyPrivateKey()
		err := r.sendRatchetPrivate.FromBytes(r.kxPrivate1.Bytes())
		if err != nil {
			return err
		}
	}

	r.ratchet = amAlice
	r.kxPrivate0.Reset()
	r.kxPrivate1.Reset()
	return nil
}

// Encrypt acts like append() but appends an encrypted version of msg to out.
func (r *Ratchet) Encrypt(out, msg []byte) ([]byte, error) {
	if r.ratchet {
		var err error
		_, r.sendRatchetPrivate, err = r.scheme.GenerateKeyPairFromEntropy(r.rand)
		if err != nil {
			return nil, err
		}
		copy(r.sendHeaderKey, r.nextSendHeaderKey)
		sharedKey := r.scheme.DeriveSecret(r.sendRatchetPrivate, r.recvRatchetPublic)

		sha := sha3.New256()
		sha.Write(rootKeyUpdateLabel)
		sha.Write(r.rootKey)
		sha.Write(sharedKey)
		keyMaterial := sha.Sum(nil)
		h := hmac.New(sha3.New256, keyMaterial)

		deriveKey(r.rootKey, rootKeyLabel, h)
		deriveKey(r.nextSendHeaderKey, headerKeyLabel, h)
		deriveKey(r.sendChainKey, chainKeyLabel, h)
		r.prevSendCount, r.sendCount = r.sendCount, 0
		r.ratchet = false
	}

	h := hmac.New(sha3.New256, r.sendChainKey)
	messageKey := make([]byte, keySize)
	deriveKey(messageKey, messageKeyLabel, h)
	deriveKey(r.sendChainKey, chainKeyStepLabel, h)

	sendRatchetPublic := r.scheme.DerivePublicKey(r.sendRatchetPrivate)

	header := make([]byte, r.headerSize)
	var headerNonce, messageNonce [nonceSize]byte
	r.randBytes(headerNonce[:])
	r.randBytes(messageNonce[:])

	binary.LittleEndian.PutUint32(header[0:4], r.sendCount)
	binary.LittleEndian.PutUint32(header[4:8], r.prevSendCount)
	copy(header[RatchetPublicKeyInHeaderOffset:], sendRatchetPublic.Bytes())
	copy(header[nonceInHeaderOffset:], messageNonce[:])
	out = append(out, headerNonce[:]...)
	out = secretbox.Seal(out, header[:], &headerNonce, array32p(r.sendHeaderKey))
	r.sendCount++

	return secretbox.Seal(out, msg, &messageNonce, array32p(messageKey)), nil
}

// trySavedKeys tries to decrypt the ciphertext using keys saved for delayed messages.
func (r *Ratchet) trySavedKeys(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < r.sealedHeaderSize {
		return nil, ErrRatchetHeaderTooSmall
	}

	sealedHeader := ciphertext[:r.sealedHeaderSize]
	var nonce [nonceSize]byte
	copy(nonce[:], sealedHeader)
	sealedHeader = sealedHeader[len(nonce):]

	for headerKey, messageKeys := range r.saved {
		header, ok := secretbox.Open(nil, sealedHeader, &nonce, &headerKey)
		if !ok {
			continue
		}
		if len(header) != r.headerSize {
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

		sealedMessage := ciphertext[r.sealedHeaderSize:]
		copy(nonce[:], header[nonceInHeaderOffset:])
		msg, ok := secretbox.Open(nil, sealedMessage, &nonce, array32p(msgKey.key))
		if !ok {
			return nil, ErrCorruptMessage
		}
		delete(messageKeys, msgNum)
		utils.ExplicitBzero(msgKey.key)
		if len(messageKeys) == 0 {
			delete(r.saved, headerKey)
			utils.ExplicitBzero(headerKey[:])
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
func (r *Ratchet) saveKeys(headerKey, recvChainKey []byte, messageNum, receivedCount uint32) (provisionalChainKey, messageKey []byte, savedKeys map[[32]byte]map[uint32]savedKey, err error) {
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

	provisionalChainKey = make([]byte, keySize)
	copy(provisionalChainKey, recvChainKey)

	for n := receivedCount; n <= messageNum; n++ {
		h := hmac.New(sha3.New256, provisionalChainKey)
		messageKey = make([]byte, keySize)
		deriveKey(messageKey, messageKeyLabel, h)
		deriveKey(provisionalChainKey, chainKeyStepLabel, h)

		if n < messageNum {
			messageKeys[n] = savedKey{messageKey, now}
		}
	}

	if messageKeys != nil {
		savedKeys = make(map[[32]byte]map[uint32]savedKey)
		savedKeys[*array32p(headerKey)] = messageKeys
	}

	return
}

// mergeSavedKeys takes a map of saved message keys from saveKeys and merges it
// into r.saved.
func (r *Ratchet) mergeSavedKeys(newKeys map[[32]byte]map[uint32]savedKey) {
	for headerKey, newMessageKeys := range newKeys {
		messageKeys, ok := r.saved[headerKey]
		if ok {
			// We already have it so Destroy the new copy.
			utils.ExplicitBzero(headerKey[:])
			for _, messageKey := range newMessageKeys {
				utils.ExplicitBzero(messageKey.key)
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
			utils.ExplicitBzero(savedKey.key)
		}
		delete(r.saved, headerKey)
		utils.ExplicitBzero(headerKey[:])
	}
}

// Decrypt decrypts a message
func (r *Ratchet) Decrypt(ciphertext []byte) ([]byte, error) {
	msg, err := r.trySavedKeys(ciphertext)
	if err != nil || msg != nil {
		return msg, err
	}

	sealedHeader := ciphertext[:r.sealedHeaderSize]
	sealedMessage := ciphertext[r.sealedHeaderSize:]
	var nonce [nonceSize]byte
	copy(nonce[:], sealedHeader)
	sealedHeader = sealedHeader[len(nonce):]

	header, ok := secretbox.Open(nil, sealedHeader, &nonce, array32p(r.recvHeaderKey))
	ok = ok && !utils.CtIsZero(r.recvHeaderKey)

	if ok {
		if len(header) != r.headerSize {
			return nil, ErrIncorrectHeaderSize
		}

		messageNum := binary.LittleEndian.Uint32(header[:4])
		provisionalChainKey, messageKey, savedKeys, err := r.saveKeys(r.recvHeaderKey, r.recvChainKey, messageNum, r.recvCount)
		if err != nil {
			return nil, err
		}

		copy(nonce[:], header[nonceInHeaderOffset:])
		msg, ok := secretbox.Open(nil, sealedMessage, &nonce, array32p(messageKey))
		if !ok {
			return nil, ErrCorruptMessage
		}

		copy(r.recvChainKey, provisionalChainKey)

		r.mergeSavedKeys(savedKeys)
		r.recvCount = messageNum + 1
		return msg, nil
	}

	header, ok = secretbox.Open(nil, sealedHeader, &nonce, array32p(r.nextRecvHeaderKey))
	if !ok {
		return nil, ErrCannotDecrypt
	}
	if len(header) != r.headerSize {
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

	theirRatchetPublic := r.scheme.NewEmptyPublicKey()
	err = theirRatchetPublic.FromBytes(header[RatchetPublicKeyInHeaderOffset : RatchetPublicKeyInHeaderOffset+r.scheme.PublicKeySize()])
	if err != nil {
		return nil, err
	}

	sharedKey := r.scheme.DeriveSecret(r.sendRatchetPrivate, theirRatchetPublic)

	sha := sha3.New256()
	sha.Write(rootKeyUpdateLabel)
	sha.Write(r.rootKey)
	sha.Write(sharedKey)

	var rootKeyHMAC hash.Hash
	chainKey := make([]byte, keySize)

	keyMaterial := sha.Sum(nil)
	rootKeyHMAC = hmac.New(sha3.New256, keyMaterial)
	deriveKey(r.rootKey, rootKeyLabel, rootKeyHMAC)
	deriveKey(chainKey, chainKeyLabel, rootKeyHMAC)

	provisionalChainKey, messageKey, savedKeys, err := r.saveKeys(r.nextRecvHeaderKey, chainKey, messageNum, 0)
	if err != nil {
		return nil, err
	}

	copy(nonce[:], header[nonceInHeaderOffset:])
	msg, ok = secretbox.Open(nil, sealedMessage, &nonce, array32p(messageKey))
	if !ok {
		return nil, ErrCorruptMessage
	}

	copy(r.recvChainKey, provisionalChainKey)
	copy(r.recvHeaderKey, r.nextRecvHeaderKey)
	deriveKey(r.nextRecvHeaderKey, headerKeyLabel, rootKeyHMAC)
	r.sendRatchetPrivate.Reset()
	r.recvRatchetPublic.FromBytes(theirRatchetPublic.Bytes())
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
		RootKey:            r.rootKey,
		SendHeaderKey:      r.sendHeaderKey,
		RecvHeaderKey:      r.recvHeaderKey,
		NextSendHeaderKey:  r.nextSendHeaderKey,
		NextRecvHeaderKey:  r.nextRecvHeaderKey,
		SendChainKey:       r.sendChainKey,
		RecvChainKey:       r.recvChainKey,
		SendRatchetPrivate: r.sendRatchetPrivate.Bytes(),
		RecvRatchetPublic:  r.recvRatchetPublic.Bytes(),
		SendCount:          r.sendCount,
		RecvCount:          r.recvCount,
		PrevSendCount:      r.prevSendCount,
		Ratchet:            r.ratchet,
	}

	if r.kxPrivate0 != nil {
		s.Private0 = r.kxPrivate0.Bytes()
	}
	if r.kxPrivate1 != nil {
		s.Private1 = r.kxPrivate1.Bytes()
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
			HeaderKey:   headerKey[:],
			MessageKeys: keys,
		})
	}

	b, _ := json.MarshalIndent(s, "", " ")
	fmt.Printf("Marshaling:\n%s\n", b)

	return s, nil
}

// DestroyRatchet destroys the ratchet
func DestroyRatchet(r *Ratchet) {
	utils.ExplicitBzero(r.rootKey)
	utils.ExplicitBzero(r.sendHeaderKey)
	utils.ExplicitBzero(r.recvHeaderKey)
	utils.ExplicitBzero(r.nextSendHeaderKey)
	utils.ExplicitBzero(r.nextRecvHeaderKey)
	utils.ExplicitBzero(r.sendChainKey)
	utils.ExplicitBzero(r.recvChainKey)
	r.sendRatchetPrivate.Reset()
	r.recvRatchetPublic.Reset()
	r.sendCount, r.recvCount = uint32(0), uint32(0)
	r.prevSendCount = uint32(0)
	if r.kxPrivate0 != nil {
		r.kxPrivate0.Reset()
	}
	if r.kxPrivate1 != nil {
		r.kxPrivate1.Reset()
	}
	r.wipeSavedKeys()
}

// headerSize is the size, in bytes, of a header's plaintext contents.
func headerSize(scheme nike.Scheme) int {
	return 4 + /* uint32 message count */
		4 + /* uint32 previous message count */
		24 + /* nonce for message */
		scheme.PublicKeySize()
}

func sealedHeaderSize(scheme nike.Scheme) int {
	// sealedHeader is the size, in bytes, of an encrypted header.
	return 24 + headerSize(scheme) + secretbox.Overhead
}

// DoubleRatchetOverhead is the number of bytes the ratchet adds in ciphertext.
func DoubleRatchetOverhead(scheme nike.Scheme) int {
	return doubleRatchetOverheadSansPubKey + scheme.PublicKeySize()
}
